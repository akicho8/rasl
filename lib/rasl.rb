# -*- coding: utf-8 -*-
#
# CASL Assembler / Simulator
#

require "optparse"
require "pathname"
require "readline"
require "kconv"

require "active_support/core_ext/string"
require "active_support/configurable"
require "active_support/core_ext/module/attribute_accessors"
require "active_support/hash_with_indifferent_access"

require "active_model"

require_relative "rasl/version"

module Rasl
  include ActiveSupport::Configurable

  config.spec             = 2
  config.bit              = 16
  config.memory_size      = 65536
  config.disassemble_rows = 8
  config.ds_init_value    = 0
  config.memory_defval    = 0
  config.bol_order        = true # 最初から命令を書けるか？
  config.dump_cols        = 8
  config.dump_rows        = 4

  class RaslError < StandardError
    def message
      [super, current_file_line].compact.join("\n")
    end

    private

    def current_file_line
      if Rasl::Parser.line_count
        if File === ARGF.file
          path = ARGF.path
        else
          path = "<STDIN>"
        end

        path_line = "#{path}:#{Rasl::Parser.line_count}: "

        to   = Rasl::Parser.scanner.pointer
        Rasl::Parser.scanner.unscan rescue nil
        from = Rasl::Parser.scanner.pointer
        padding = ' ' * (path_line.size + from)

        out = []
        out << "-" * 75
        out << "#{path_line}#{Rasl::Parser.raw_line.rstrip}"
        if to != from
          out << padding + '^' * (to - from)
        else
          out << padding + '^'
        end
        out << "-" * 75
        out << Rasl::Parser.scanner.inspect
        out * "\n"
      end
    end
  end

  # 主にアセンブル時のエラー
  class SyntaxError          < RaslError;   end
  class LabelNotFound        < SyntaxError; end
  class LabelDuplicate       < SyntaxError; end
  class InvalidIndexRegister < SyntaxError; end
  class InvalidOrder         < SyntaxError; end
  class RegisterNotFound     < SyntaxError; end

  # 実行時エラー
  class RunError      < RaslError; end
  class MemoryViolate < RunError; end

  class Operand
    include ActiveModel::Model
    attr_accessor :key, :encode, :decode, :op_code, :printer, :with_imm, :alias

    def ==(object)
      case object
      when Integer
        op_code == object
      else
        match_names.include?(object.to_s.downcase)
      end
    end

    def match_names
      [key, self.alias].flatten.compact.collect(&:to_s)
    end

    def name
      key.upcase.to_s
    end
  end

  class Value
    class << self
      def cast_value(value, signed)
        format = {8 => "c", 16 => "s", 32 => "l", 64 => "q"}.fetch(Value.bit)
        [value].pack(format).unpack(signed ? format : format.upcase).first
      end

      def signed(value)
        cast_value(value, true)
      end

      def unsigned(value)
        cast_value(value, false)
      end

      def lsb
        1
      end

      def msb
        1 << (bit - 1)
      end

      def signed_min
        -1 << (bit - 1)
      end

      def signed_max
        (1 << (bit - 1)) - 1
      end

      def unsigned_min
        0
      end

      def unsigned_max
        (1 << bit) - 1
      end

      def bit
        Rasl.config.bit
      end

      def signed_range
        signed_min .. signed_max
      end

      def unsigned_range
        unsigned_min .. unsigned_max
      end

      def hex_format(value)
        "%0*X" % [hex_width, unsigned(value)]
      end

      def hex_width
        bit / 4
      end
    end

    def initialize(raw = 0)
      @raw = raw
    end

    def reset
      @raw = 0
    end

    def u_value
      self.class.unsigned(@raw)
    end
    alias value u_value
    alias logical u_value
    alias unsigned u_value

    def u_value=(v)
      @raw = self.class.unsigned(v)
    end
    alias value= u_value=;
    alias logical= u_value=;
    alias unsigned= u_value=;

    def s_value
      self.class.signed(@raw)
    end
    alias arithmetic s_value
    alias signed s_value

    def s_value=(v)
      @raw = self.class.signed(v)
    end
    alias arithmetic= s_value=;
    alias signed= s_value=;

    def hex_format
      self.class.hex_format(@raw)
    end
    alias to_s hex_format
  end

  class Register < Value
    attr_reader :key

    def initialize(key, attributes = {})
      super()
      @key = key.to_sym
      @attributes = attributes
    end

    def pos
      @attributes[:pos]
    end

    def to_s
      "#{name}=#{super}"
    end

    def useful_as_xr?
      pos && pos.nonzero?
    end

    def name
      @key.upcase.to_s
    end
  end

  class NullRegister < Register
    def initialize(code)
      super("gr#{code}(?)")
    end
  end

  class FlagRegister < Register
    cattr_accessor :flags_hash do
      {
        :of => (1 << 2),
        :sf => (1 << 1),
        :zf => (1 << 0),
      }
    end

    def to_s
      "%s=%s(%s)" % [name, to_s_flags, to_s_sign]
    end

    def to_s_flags
      flags_hash.keys.collect do |key|
        send("#{key}?") ? key.to_s[0].upcase : "_"
      end.join
    end

    def to_s_sign
      case
      when sf?
        "-"
      when zf?
        "0"
      else
        "+"
      end
    end

    def available_flags
      flags_hash.keys.each_with_object([]) do |key, a|
        if send("#{key}?")
          a << key
        end
      end
    end

    flags_hash.each do |key, bit|
      define_method(key) do
        !!(@raw & bit).nonzero?
      end

      alias_method "#{key}?", key

      define_method("#{key}=") do |flag|
        flag.tap do
          @raw &= ~bit
          if flag
            @raw |= bit
          end
        end
      end
    end
  end

  module Env
    attr_reader :gr, :memory, :global_labels, :labels
    attr_accessor :exit_key, :code_size, :boot_pc

    def initialize
      create_registers

      @gr[:pr] = @gr[:pc]
      if Rasl.config.spec == 1
        @gr[:sp] = @gr.values.last
      end

      @memory = Array.new(Rasl.config.memory_size)

      @operands = operand_list.collect{|v|Operand.new(v)}
      @operands_hash = @operands.inject(ActiveSupport::HashWithIndifferentAccess.new){|h, o|h.merge(o.key => o)}

      @code_size = 0
      @boot_pc = 0

      init_env
    end

    def init_env
      @labels = Hash.new
      @memory.fill(Rasl.config.memory_defval)
      @gr.values.each(&:reset)
      @inline_addr_list = []
    end

    def assemble(buffer)
      init_env
      assemble_without_init_env(buffer)
    end

    def assemble_without_init_env(buffer)
      @current_buffer = buffer
      @pass_count = 0
      assemble_once
      @pass_count += 1
      assemble_once
      self
    end

    def disassemble
      out = ""
      pc = 0
      until pc >= @code_size
        code_fetch(pc)
        pc = @cur_code[:next_pc]
        out << disasm_current << "\n"
      end
      out
    end

    def create_map_file(map_file)
      Pathname(map_file).open("w"){|f|f << disassemble}
    end

    def gr_count
      Rasl.config.spec == 1 ? 5 : 8
    end

    def store_object(gr: nil, imm: nil, xr: nil)
      raise SyntaxError if (gr && !gr.pos) || (gr && !gr.pos)
      store_prim_op(@current_op.op_code, (gr ? gr.pos : nil), (xr ? xr.pos : nil), imm)
    end

    def store_prim_op(op_code, r1, r2, imm = nil)
      store_value((op_code << 8) | (((r1 || 0) & 0xf) << 4) | ((r2 || 0) & 0xf))
      if imm
        store_value(imm)
      end
    end

    def store_value(value)
      @memory[@code_size] = value
      @code_size += 1
      @encoded = true
    end

    def code_fetch(pc)
      @cur_code = prefetch(pc)
    end

    def disasm_current
      if @cur_code[:operand] && @cur_code[:operand].decode
        params = disasm_op
      else
        params = disasm_dc
      end
      ("%04X %s %-*s    %-7s %s" % [@cur_code[:addr], Value.hex_format(@cur_code[:raw]), Value.hex_width, *params]).strip
    end

    def disasm_op
      arg = ""
      if @cur_code[:operand].printer
        arg = send(@cur_code[:operand].printer)
      end
      [(@cur_code[:imm] ? Value.hex_format(@cur_code[:imm]) : ""), @cur_code[:operand].name, arg]
    end

    def disasm_dc
      arg = "%-*d" % [Value.signed_min.to_s.length, Value.signed(@cur_code[:raw])]
      begin
        if @cur_code[:raw].chr.match(/[[:print:]]/)
          arg << " ; '#{@cur_code[:raw].chr}'"
        end
      rescue RangeError
      end
      ["", "DC", arg]
    end

    def code_dump
      mem_dump(@memory, :range => 0...@code_size)
    end

    def regs_info
      out = []
      out += gr_count.times.collect{|i|@gr["gr#{i}"]}.collect(&:to_s)
      out += [@gr[:pc], @gr[:sp], @gr[:fr]].collect(&:to_s)
      out << (@exit_key ? "[#{@exit_key}]" : nil)
      out.join(" ").strip
    end

    def info
      [regs_info, @labels.inspect] * "\n"
    end
    alias to_s info

    def label_fetch(str)
      ((@labels[@namespace] || {})[str]) || ((@labels["__global__"] || {})[str])
    end

    private

    def create_registers
      @gr = ActiveSupport::HashWithIndifferentAccess.new
      gr_count.times do |i|
        r = Register.new("gr#{i}", :pos => @gr.count)
        @gr[r.key] = r
        # @gr[i.to_s] = r # for CASL1
      end

      if Rasl.config.spec == 2
        @gr[:sp] = Register.new(:sp, :pos => @gr.count)
      end

      @gr[:pc] = Register.new(:pc, :pos => @gr.count)
      @gr[:fr] = FlagRegister.new(:fr, :pos => @gr.count)
    end

    def assemble_once
      Rasl::Parser.line_count = 0

      @code_size = 0
      @boot_pc = nil

      @inline_dc_list = []
      @inline_index = 0

      @start_index = 0
      @namespace = "__global__"
      @namespaces = []

      @current_buffer.lines.each do |line|
        Rasl::Parser.raw_line = line
        Rasl::Parser.line_count += 1
        line = line.sub(syntax[:comment], "").rstrip
        if line.blank?
          next
        end
        @scanner = StringScanner.new(line)
        Rasl::Parser.scanner = @scanner
        parse_label_part
        skip_blank
        parse_order_part
      end

      inline_dc_store

      Rasl::Parser.scanner = nil
      Rasl::Parser.line_count = nil
      Rasl::Parser.raw_line = nil
    end

    def parse_label_part
      @current_label = nil
      if label = @scanner.scan(/#{syntax[:label]}:?/)
        if Rasl.config.bol_order && !label.end_with?(":") && @operands.collect(&:match_names).flatten.include?(label.downcase)
          @scanner.unscan
        else
          label = label.sub(":", "")
          if label_fetch(label) && @pass_count == 0
            raise LabelDuplicate, "ラベル重複 : #{label.inspect}"
          end
          @labels[@namespace] ||= {}
          @labels[@namespace].update(label => @code_size)
          @current_label = label
        end
      end
    end

    def parse_order_part
      if str = @scanner.scan(syntax[:symbol])
        @encoded = false
        skip_blank
        pointer = @scanner.pointer
        @operands.each do |operand|
          if operand == str
            @current_op = operand
            @scanner.pointer = pointer
            send operand.encode
            if @encoded
              break
            end
          end
        end
        unless @encoded
          raise InvalidOrder, "無効な命令 : #{str.inspect}"
        end
      end
    end

    def mem_set(index, value)
      valid_addr(index)
      @memory[index] = Value.unsigned(value)
    end

    def mem_get(index)
      valid_addr(index)
      Value.unsigned(@memory[index])
    end

    def valid_addr(index)
      unless @memory[index]
        raise MemoryViolate, "メモリの外にアクセスしました : #{index} メモリサイズ:#{@memory.size}"
      end
    end

    def mem_dump(memory, options = {})
      options = {
        columns: Rasl.config.dump_cols,
        range: 0...memory.size,
      }.merge(options)

      pos = options[:range].begin
      if body = memory[options[:range]]
        body.each_slice(options[:columns]) do |values|
          chars = values.collect do |value|
            begin
              value.chr
            rescue RangeError
              "."
            end
          end
          puts "%04X: %-*s%s" % [
            pos,
            (Value.hex_width + 1) * options[:columns],
            values.collect{|v|Value.hex_format(v)} * " ",
            chars.join.gsub(/[[:^print:]]/, "."),
          ]
          pos += values.length
        end
      end
    end

    def store_object(gr: nil, imm: nil, xr: nil)
      raise SyntaxError if gr && !gr.pos
      raise SyntaxError if xr && !xr.pos
      store_prim_op(@current_op.op_code, (gr ? gr.pos : nil), (xr ? xr.pos : nil), imm)
    end

    def store_prim_op(op_code, r1, r2, imm = nil)
      store_value((op_code << 8) | (((r1 || 0) & 0xf) << 4) | ((r2 || 0) & 0xf))
      if imm
        store_value(imm)
      end
    end

    def store_asm(key, *args)
      args = args.collect{|e|e.kind_of?(Symbol) ? @gr[e].pos : e}
      store_prim_op(@operands_hash[key].op_code, *args)
    end

    def store_value(value)
      @memory[@code_size] = value
      @code_size += 1
      @encoded = true
    end

    def code_fetch(pc)
      @cur_code = prefetch(pc)
    end

    def prefetch(pc)
      attrs = {}

      attrs[:addr] = pc
      attrs[:raw] = mem_get(pc)

      pc += 1
      attrs[:op_code] = (attrs[:raw] >> 8) & 0xff
      attrs[:operand] = @operands.find{|e|e == attrs[:op_code] && e.decode}

      r1_r2 = attrs[:raw] & 0xff

      r1 = (r1_r2 >> 4) & 0xf
      attrs[:r1] = @gr.values.find{|e|e.pos == r1} || NullRegister.new(r1)
      attrs[:r] = attrs[:r1]

      r2 = r1_r2 & 0xf
      attrs[:r2] = @gr.values.find{|e|e.pos == r2} || NullRegister.new(r2)
      attrs[:xr] = @gr.values.find{|e|e.pos == r2 && e.useful_as_xr?}

      if attrs[:operand] && attrs[:operand].with_imm
        attrs[:imm] = mem_get(pc)
        pc += 1

        attrs[:imm_xr] = attrs[:imm]
        if attrs[:xr]
          attrs[:imm_xr] += attrs[:xr].value
        end
      end

      attrs[:next_pc] = pc

      attrs.freeze
    end
  end

  module OperandPresets1
    private

    def operand_list
      [
        { key: :nop,  op_code: 0x09, encode: :encode_blank,                decode: :decode_nop                                      },

        { key: :ld,   op_code: 0x10, encode: :encode_rix,  with_imm: true, decode: :decode_ld_rix,   printer: :prt_rix              },
        { key: :st,   op_code: 0x11, encode: :encode_rix,  with_imm: true, decode: :decode_st_rix,   printer: :prt_rix              },
        { key: :lad,  op_code: 0x12, encode: :encode_rixf, with_imm: true, decode: :decode_lad_rix,  printer: :prt_rix              },
        { key: :ld,   op_code: 0x14, encode: :encode_r_r,                  decode: :decode_ld_r_r,   printer: :prt_r_r              },
        { key: :lea,  op_code: 0x1f, encode: :encode_rix,  with_imm: true, decode: :decode_lea_rix,  printer: :prt_rix              },

        { key: :adda, op_code: 0x20, encode: :encode_rix,  with_imm: true, decode: :decode_adda_rix, printer: :prt_rix, alias: :add },
        { key: :suba, op_code: 0x21, encode: :encode_rix,  with_imm: true, decode: :decode_suba_rix, printer: :prt_rix, alias: :sub },
        { key: :addl, op_code: 0x22, encode: :encode_rix,  with_imm: true, decode: :decode_addl_rix, printer: :prt_rix              },
        { key: :subl, op_code: 0x23, encode: :encode_rix,  with_imm: true, decode: :decode_subl_rix, printer: :prt_rix              },
        { key: :adda, op_code: 0x24, encode: :encode_r_r,                  decode: :decode_adda_r_r, printer: :prt_r_r              },
        { key: :suba, op_code: 0x25, encode: :encode_r_r,                  decode: :decode_suba_r_r, printer: :prt_r_r              },
        { key: :addl, op_code: 0x26, encode: :encode_r_r,                  decode: :decode_addl_r_r, printer: :prt_r_r              },
        { key: :subl, op_code: 0x27, encode: :encode_r_r,                  decode: :decode_subl_r_r, printer: :prt_r_r              },

        { key: :and,  op_code: 0x30, encode: :encode_rix,  with_imm: true, decode: :decode_and_rix,  printer: :prt_rix              },
        { key: :or,   op_code: 0x31, encode: :encode_rix,  with_imm: true, decode: :decode_or_rix,   printer: :prt_rix              },
        { key: :xor,  op_code: 0x32, encode: :encode_rix,  with_imm: true, decode: :decode_xor_rix,  printer: :prt_rix, alias: :eor },
        { key: :and,  op_code: 0x34, encode: :encode_r_r,                  decode: :decode_and_r_r,  printer: :prt_r_r              },
        { key: :or,   op_code: 0x35, encode: :encode_r_r,                  decode: :decode_or_r_r,   printer: :prt_r_r              },
        { key: :xor,  op_code: 0x36, encode: :encode_r_r,                  decode: :decode_xor_r_r,  printer: :prt_r_r              },

        { key: :cpa,  op_code: 0x40, encode: :encode_rix,  with_imm: true, decode: :decode_cpa_rix,  printer: :prt_rix              },
        { key: :cpl,  op_code: 0x41, encode: :encode_rix,  with_imm: true, decode: :decode_cpl_rix,  printer: :prt_rix              },
        { key: :cpa,  op_code: 0x44, encode: :encode_r_r,                  decode: :decode_cpa_r_r,  printer: :prt_r_r              },
        { key: :cpl,  op_code: 0x45, encode: :encode_r_r,                  decode: :decode_cpl_r_r,  printer: :prt_r_r              },

        { key: :sla,  op_code: 0x50, encode: :encode_rix,  with_imm: true, decode: :decode_sla_rix,  printer: :prt_rix              },
        { key: :sra,  op_code: 0x51, encode: :encode_rix,  with_imm: true, decode: :decode_sra_rix,  printer: :prt_rix              },
        { key: :sll,  op_code: 0x52, encode: :encode_rix,  with_imm: true, decode: :decode_sll,      printer: :prt_rix              },
        { key: :srl,  op_code: 0x53, encode: :encode_rix,  with_imm: true, decode: :decode_srl,      printer: :prt_rix              },

        { key: :jpz,  op_code: 0x60, encode: :encode_ix,   with_imm: true, decode: :decode_jpz,      printer: :prt_ix               },
        { key: :jmi,  op_code: 0x61, encode: :encode_ix,   with_imm: true, decode: :decode_jmi,      printer: :prt_ix               },
        { key: :jnz,  op_code: 0x62, encode: :encode_ix,   with_imm: true, decode: :decode_jnz,      printer: :prt_ix               },
        { key: :jze,  op_code: 0x63, encode: :encode_ix,   with_imm: true, decode: :decode_jze,      printer: :prt_ix               },
        { key: :jump, op_code: 0x64, encode: :encode_ix,   with_imm: true, decode: :decode_jump,     printer: :prt_ix, alias: :jmp  },
        { key: :jpl,  op_code: 0x65, encode: :encode_ix,   with_imm: true, decode: :decode_jpl,      printer: :prt_ix               },
        { key: :jov,  op_code: 0x66, encode: :encode_ix,   with_imm: true, decode: :decode_jov,      printer: :prt_ix               },

        { key: :push, op_code: 0x70, encode: :encode_ix,   with_imm: true, decode: :decode_push,     printer: :prt_ix               },
        { key: :pop,  op_code: 0x71, encode: :encode_gr,                   decode: :decode_pop,      printer: :prt_gr               },
        { key: :call, op_code: 0x80, encode: :encode_ix,   with_imm: true, decode: :decode_call,     printer: :prt_ix               },
        { key: :ret,  op_code: 0x81, encode: :encode_blank,                decode: :decode_ret                                      },

        { key: :svc,  op_code: 0xf0, encode: :encode_ix,   with_imm: true, decode: :decode_svc,      printer: :prt_ix               },

        { key: :prt,  op_code: 0xe0, encode: :encode_ix,   with_imm: true, decode: :decode_prt,      printer: :prt_ix               },

        { key: :start,               encode: :encode_start                                                                          },
        { key: :end,                 encode: :encode_end                                                                            },
        { key: :ds,                  encode: :encode_ds                                                                             },
        { key: :dc,                  encode: :encode_dc                                                                             },

        { key: :in,                  encode: :encode_in                                                                             },
        { key: :out,                 encode: :encode_out                                                                            },
        { key: :exit,                encode: :encode_exit                                                                           },
        { key: :rpush,               encode: :encode_rpush                                                                          },
        { key: :rpop,                encode: :encode_rpop                                                                           },

        { key: :copy,                encode: :encode_copy                                                                           },
      ]
    end

    def encode_blank
      store_object
    end

    def encode_r_r
      r1 = scan_gr
      skip_sep
      if @scanner.check(register_regexp)
        store_object(gr: r1, xr: scan_gr)
      end
    end

    def encode_rix
      r1 = scan_gr
      skip_sep
      unless @scanner.check(register_regexp)
        store_object(gr: r1, imm: scan_imm, xr: scan_xr)
      end
    end

    def encode_rixf
      r1 = scan_gr
      skip_sep
      store_object(gr: r1, imm: scan_imm, xr: scan_xr)
    end

    def encode_gr
      store_object(gr: scan_gr)
    end

    def encode_ix
      store_object(imm: scan_imm, xr: scan_xr)
    end

    def encode_imm
      store_object(imm: scan_imm)
    end

    def encode_in
      encode_inout(:input)
    end

    def encode_out
      encode_inout(:output)
    end

    def encode_inout(function)
      store_asm :push, nil, :gr1, 0
      store_asm :push, nil, :gr2, 0
      store_asm :lad, :gr1, 0, scan_imm
      skip_sep
      store_asm :lad, :gr2, 0, scan_imm
      store_asm :svc, nil, nil, svc_hash[function][:code]
      store_asm :pop, :gr2, nil
      store_asm :pop, :gr1, nil
    end

    def encode_copy
      store_asm :push, nil, :gr1, 0
      store_asm :push, nil, :gr2, 0
      store_asm :push, nil, :gr3, 0
      store_asm :lad, :gr1, 0, scan_imm
      skip_sep
      store_asm :lad, :gr2, 0, scan_imm
      skip_sep
      store_asm :lad, :gr3, 0, scan_imm
      store_asm :svc, nil, nil, svc_hash[:copy][:code]
      store_asm :pop, :gr3, nil
      store_asm :pop, :gr2, nil
      store_asm :pop, :gr1, nil
    end

    def encode_exit
      store_prim_op(@operands_hash[:svc].op_code, nil, nil, svc_hash[:exit][:code])
    end

    def encode_start
      @start_index += 1

      @namespaces.push(@namespace)
      if @current_label
        @namespace = @current_label
      else
        @namespace = "__proc_#{@start_index}"
      end

      v = 0
      if @scanner.check(/\S+/)
        v = scan_imm
      end
      @boot_pc ||= v

      @encoded = true
    end

    def encode_end
      inline_dc_store
      @namespace = @namespaces.pop
      @encoded = true
    end

    def inline_dc_store
      @inline_dc_list.each do |v|
        @inline_addr_list << @code_size
        dc_store(v)
      end
      @inline_dc_list.clear
    end

    def encode_dc
      loop do
        dc_store(scan_imm_or_str)
        skip_sep
        if @scanner.eos?
          break
        end
      end
      @encoded = true
    end

    def dc_store(value)
      if value.kind_of? String
        value.each_byte{|ch|store_value(ch)}
      else
        store_value(value)
      end
    end

    def scan_imm_or_str
      if str = scan_str_literal(%{'}) || scan_str_literal(%{"})
        str
      else
        scan_imm
      end
    end

    def scan_str_literal(mark)
      if @scanner.check(/#{mark}/)
        from = @scanner.pointer
        nil while @scanner.scan(/#{mark}[^#{mark}]*#{mark}/) && @scanner.check(/#{mark}/)
        str = @scanner.string[from...@scanner.pointer] # 【'a''b'】
        if str == ""
          raise SyntaxError, "対応する #{mark} がない"
        end
        str = str.match(/\A.(?<str>.*).\z/)[:str]      # 【a''b】
        str.gsub(/#{mark}{2}/, mark)                   # 【a'b】
      end
    end

    def encode_ds
      scan_imm.times.each{store_value(Rasl.config.ds_init_value)}
      @encoded = true
    end

    def decode_ld_rix
      @cur_code[:r1].value = mem_get(@cur_code[:imm_xr])
      set_fr(@cur_code[:r1].s_value)
      @gr[:fr].of = false
    end

    def decode_ld_r_r
      @cur_code[:r1].value = @cur_code[:r2].value
      set_fr(@cur_code[:r1].s_value)
      @gr[:fr].of = false
    end

    def decode_st_rix
      mem_set(@cur_code[:imm_xr], @cur_code[:r1].value)
    end

    def decode_lea_rix
      decode_lad_rix
      set_fr(@cur_code[:r1].s_value)
    end

    def decode_lad_rix
      @cur_code[:r1].value = @cur_code[:imm_xr]
    end

    def decode_adda_rix
      decode_calc(:+, :rix, :signed)
    end

    def decode_addl_rix
      decode_calc(:+, :rix, :unsigned)
    end

    def decode_suba_rix
      decode_calc(:-, :rix, :signed)
    end

    def decode_subl_rix
      decode_calc(:-, :rix, :unsigned)
    end

    def decode_adda_r_r
      decode_calc(:+, :r_r, :signed)
    end

    def decode_suba_r_r
      decode_calc(:-, :r_r, :signed)
    end

    def decode_addl_r_r
      decode_calc(:+, :r_r, :unsigned)
    end

    def decode_subl_r_r
      decode_calc(:-, :r_r, :unsigned)
    end

    def decode_and_rix
      decode_logical_bit(:&, mem_get(@cur_code[:imm_xr]))
    end

    def decode_or_rix
      decode_logical_bit(:|, mem_get(@cur_code[:imm_xr]))
    end

    def decode_xor_rix
      decode_logical_bit(:^, mem_get(@cur_code[:imm_xr]))
    end

    def decode_and_r_r
      decode_logical_bit(:&, @cur_code[:r2].value)
    end

    def decode_or_r_r
      decode_logical_bit(:|, @cur_code[:r2].value)
    end

    def decode_xor_r_r
      decode_logical_bit(:^, @cur_code[:r2].value)
    end

    def decode_calc(method, syntax_type, value_type)
      v1 = @cur_code[:r1].value
      if syntax_type == :r_r
        v2 = @cur_code[:r2].value
      else
        v2 = mem_get(@cur_code[:imm_xr])
      end
      v1 = Value.send(value_type, v1)
      v2 = Value.send(value_type, v2)
      value = v1.send(method, v2)
      @gr[:fr].of = !Value.send("#{value_type}_range").include?(value)
      @cur_code[:r1].value = value
      set_fr(@cur_code[:r1].s_value)
    end

    def decode_logical_bit(method, right_value)
      @cur_code[:r1].value = @cur_code[:r1].value.send(method, right_value)
      set_fr(@cur_code[:r1].s_value)
      @gr[:fr].of = false
    end

    def decode_cpa_rix
      decode_cpx(mem_get(@cur_code[:imm_xr]), :signed)
    end

    def decode_cpl_rix
      decode_cpx(mem_get(@cur_code[:imm_xr]), :unsigned)
    end

    def decode_cpa_r_r
      decode_cpx(@cur_code[:r2].value, :signed)
    end

    def decode_cpl_r_r
      decode_cpx(@cur_code[:r2].value, :unsigned)
    end

    def decode_cpx(right_value, value_type)
      set_fr(Value.send(value_type, @cur_code[:r1].value) - Value.send(value_type, right_value))
      @gr[:fr].of = false
    end

    def set_fr(value)
      @gr[:fr].zf = value.zero?
      @gr[:fr].sf = value < 0
    end

    def set_of(value)
      @gr[:fr].of = value.nonzero?
    end

    def decode_sla_rix
      decode_sxa(:<<, :signed)
    end

    def decode_sra_rix
      decode_sxa(:>>, :signed)
    end

    def decode_sll
      decode_sxa(:<<, :unsigned)
    end

    def decode_srl
      decode_sxa(:>>, :unsigned)
    end

    def decode_sxa(method, value_type)
      shift = mem_get(@cur_code[:imm_xr])
      if shift > Value.bit
        shift = Value.bit
      end
      of_bit = (method == :<< ? Value.msb : Value.lsb)
      v = @cur_code[:r1].send(value_type)
      of = 0
      shift.times do
        of = v & of_bit
        sf_bit = (v & Value.msb)
        v = v.send(method, 1)
        if value_type == :signed
          v |= sf_bit
        end
      end
      @cur_code[:r1].value = v
      set_fr(@cur_code[:r1].s_value)
      set_of(of)
    end

    def decode_jpz
      unless @gr[:fr].sf?
        decode_jump
      end
    end

    def decode_jmi
      if @gr[:fr].sf?
        decode_jump
      end
    end

    def decode_jnz
      unless @gr[:fr].zf?
        decode_jump
      end
    end

    def decode_jze
      if @gr[:fr].zf?
        decode_jump
      end
    end

    def decode_jump
      @gr[:pc].value = @cur_code[:imm_xr]
    end

    def decode_push
      value_push(@cur_code[:imm_xr])
    end

    def value_push(value)
      @gr[:sp].value -= 1
      mem_set(@gr[:sp].value, value)
    end

    def value_pop
      mem_get(@gr[:sp].value).tap do
        @gr[:sp].value += 1
      end
    end

    def decode_pop
      @cur_code[:r1].value = value_pop
    end

    def decode_call
      value_push(@gr[:pc].value)
      decode_jump
    end

    def decode_ret
      @gr[:pc].value = value_pop
      if @gr[:sp].value >= @memory.size || @gr[:sp].value == 0
        @exit_key = :ret
      end
    end

    def decode_nop
    end

    def decode_svc
      if elem = svc_list.find{|e|e[:code] == @cur_code[:imm_xr]}
        send "decode_svc_#{elem[:key]}"
      end
    end

    def svc_list
      [
        {:key => :input,  :code => 0},
        {:key => :output, :code => 1},
        {:key => :exit,   :code => 2},
        {:key => :copy,   :code => 3},
      ]
    end

    def svc_hash
      svc_list.inject({}){|h, v|h.merge(v[:key] => v)}
    end

    def decode_svc_input
      base = @gr[:gr1].value
      len  = @gr[:gr2].value
      str = gets.to_s.rstrip
      str.chars.each.with_index{|ch, i|
        mem_set(base + i, ch.ord)
      }
      mem_set(len, str.length)
    end

    def decode_svc_output
      base = @gr[:gr1].value
      len  = @gr[:gr2].value
      str = mem_get(len).times.collect{|i|
        v = mem_get(base + i)
        begin
          v.chr
        rescue RangeError
          "(##{Value.hex_format(v)})"
        end
      }.join
      puts str
    end

    def decode_svc_exit
      @exit_key = :exit
    end

    def decode_svc_copy
      dst = @gr[:gr1].value
      src = @gr[:gr2].value
      len = @gr[:gr3].value
      len.times do |i|
        mem_set(dst + i, mem_get(src + i))
      end
    end

    def decode_prt
      puts @cur_code[:imm_xr]
    end

    def prt_r_r
      [@cur_code[:r1].name, separator, @cur_code[:r2].name].join
    end

    def prt_rix
      [prt_gr, separator, prt_ix].join
    end

    def prt_ix
      ["##{Value.hex_format(@cur_code[:imm])}", prt_xr].join
    end

    def prt_gr
      @cur_code[:r1].name
    end

    def prt_xr
      if @cur_code[:xr]
        "#{separator}#{@cur_code[:xr].name}"
      end
    end

    def separator
      ", "
    end

    def prt_blank
    end
  end

  module OperandPresets2
    def decode_jpl
      if !@gr[:fr].sf? && !@gr[:fr].zf?
        decode_jump
      end
    end

    def decode_jov
      if @gr[:fr].of?
        decode_jump
      end
    end

    def encode_rpush
      rpush_registers.each do |r|
        store_prim_op(@operands_hash[:push].op_code, 0, r.pos, 0)
      end
    end

    def encode_rpop
      rpush_registers.reverse_each do |r|
        store_prim_op(@operands_hash[:pop].op_code, r.pos, 0)
      end
    end

    def rpush_registers
      (1 ... gr_count).collect{|i|@gr["gr#{i}"]}
    end
  end

  module Parser
    mattr_accessor :raw_line, :line_count, :scanner

    private

    def syntax
      {
        :comment   => /([^\\];|\A#).*/,
        :label     => /\A[$@_a-z]\w*/i,
        :symbol    => /\A[_a-z]\w*/i,
        :imm       => /[+-]?(#|0x|0b)?[\da-f]+/i,
        :sepalator => /[,\s]+/,  # 厳密にするなら /\s*,\s*/
        :blank     => /[,\s]+/,  # 厳密にするなら /\s+/
        :inline_dc => /\s*=\s*/i,
      }
    end

    def register_regexp
      Regexp.union(/\b#{@gr.keys.join("|")}\b/i)
    end

    def scan_gr
      if str = @scanner.scan(register_regexp)
        @gr[str.downcase]
      else
        raise RegisterNotFound, "レジスタの指定がありません"
      end
    end

    def scan_imm
      case
      when str = @scanner.scan(syntax[:label])
        if @pass_count == 0
          undecision
        else
          v = label_fetch(str)
          unless v
            raise LabelNotFound, "ラベルが見つかりません : #{str.inspect} in #{@labels.inspect}"
          end
          v
        end
      when str = @scanner.scan(syntax[:imm])
        cast_int(str)
      when @scanner.scan(syntax[:inline_dc])
        @inline_dc_list << scan_imm_or_str
        if @pass_count == 0
          v = undecision
        else
          v = @inline_addr_list[@inline_index]
        end
        @inline_index += 1
        v
      else
        raise SyntaxError, "即値が見つかりません"
      end
    end

    def scan_xr
      skip_sep
      if str = @scanner.scan(register_regexp)
        xr = @gr[str.downcase]
        unless xr
          raise SyntaxError, "指標レジスタの表記が間違っています : #{str.inspect}"
        end
        unless xr.useful_as_xr?
          raise InvalidIndexRegister, "指標レジスタに #{xr.name} は使えません"
        end
      end
      xr
    end

    def imm_or_int(str)
      case
      when v = label_fetch(str)
        v
      when str.match(syntax[:imm])
        cast_int(str)
      end
    end

    def cast_int(str)
      Integer(str.sub(/\A#/, "0x"))
    end

    def label_or_imm_regexp
      Regexp.union(syntax[:label], syntax[:imm])
    end

    def skip_sep
      @scanner.skip(syntax[:sepalator])
    end

    def skip_blank
      @scanner.skip(syntax[:blank])
    end

    def undecision
      -1
    end
  end

  module Simulator
    def simulator
      command_init
      loop do
        if defined? Readline
          getline(Readline.readline("-"))
        else
          print "-"
          getline(STDIN.gets)
        end
        if @command
          if @command == "q"
            break
          end
          if command = command_table[@command]
            send command
          end
        end
      end
    end

    def go
      command_init
      command_go
      self
    end

    def command_table
      {
        'i' => :command_init,
        'g' => :command_go,
        'r' => :command_register,
        'd' => :command_dump,
        't' => :command_trace,
        'u' => :command_disasm,
        '?' => :command_help,
        'h' => :command_help,
      }
    end

    def command_dump
      if @hex_args
        @dump_point = @hex_args.first
      end
      size = Rasl.config.dump_cols * Rasl.config.dump_rows
      mem_dump(@memory, :range => (@dump_point...(@dump_point + size)))
      @dump_point += size
    end

    def command_disasm
      if @hex_args
        @unencode_point = @hex_args.first
      end
      Rasl.config.disassemble_rows.times do
        if @unencode_point >= @memory.size
          break
        end
        code_fetch(@unencode_point)
        @unencode_point = @cur_code[:next_pc]
        puts disasm_current
      end
    end

    def command_init
      @gr.values.each(&:reset)
      before_go
    end

    def before_go
      @gr[:sp].value = @memory.size
      value_push(-1)

      @boot_pc ||= 0
      @gr[:pc].value = @boot_pc
      @unencode_point = @boot_pc
      @dump_point = @boot_pc

      @exit_key = false
    end

    def command_go
      set_pc
      until @exit_key
        command_step
      end
    end

    def command_trace
      set_pc
      command_step
      current_state
    end

    def command_register
      if @args
        @args.each do |arg|
          if md = arg.match(/(?<lhv>.+)=(?<rhv>.+)/)
            @gr[md[:lhv].downcase].value = imm_or_int(md[:rhv])
          end
        end
      else
        current_state
      end
    end

    def command_step
      code_fetch(@gr[:pc].value)
      unless @cur_code[:operand]
        raise RunError, "不明な命令のため実行できません : #{@cur_code[:raw]}"
      end
      @gr[:pc].value = @cur_code[:next_pc]
      send @cur_code[:operand].decode
    end

    def current_state
      code_fetch(@gr[:pc].value)
      puts regs_info
      puts disasm_current
    end

    def post_command(s)
      getline(s)
      send command_table[@command]
    end

    private

    def getline(s)
      @command = nil
      @args = nil
      @hex_args = nil
      if md = s.strip.match(/(.)(.*)/)
        @command, _args = md.captures.to_a
        @command = @command.downcase
        unless _args.empty?
          @args = _args.split(/\s+|,/)
          @hex_args = @args.collect{|e|e.to_i(16)}
        end
      end
    end

    def set_pc
      if @hex_args
        @gr[:pc].value = @hex_args.first
      end
    end

    def command_help
      puts <<-EOT
D[address]    memory-dump
U[address]    unassemble
G[address]    go
T[address]    trace
R[reg=n]      register
? or H        usage
I             init
Q             quit
EOT
    end
  end

  class Processor
    prepend Env
    prepend OperandPresets1
    prepend OperandPresets2
    prepend Parser
    prepend Simulator
  end

  class CLI
    def self.execute(args = ARGV)
      new.execute(args)
    end

    def initialize
      @file = nil
      @options = {}
    end

    def parser
      OptionParser.new do |o|
        o.version = VERSION
        o.banner = [
          "CASL Assembler / Simulator #{o.ver}\n",
          "使い方: #{o.program_name} [OPTIONS] [ファイル]\n",
        ].join
        o.on("-s", "--simulator", "シミュレーターを起動する") do |v|
          @options[:simulator] = v
        end
        o.on("-p", "--print-map", "MAP情報を標準出力する") do |v|
          @options[:print_map] = v
        end
        o.on("-g", "--go", "実行する") do |v|
          @options[:go] = v
        end
        o.on("-m", "--output-map", "MAPファイルを出力する。-g オプションがあるときは実行後に出力する") do |v|
          @options[:output_map] = v
        end
        o.on("-e CODE", "--eval=CODE", "アセンブルするコード。指定があると標準入力からは読み込まない") do |v|
          @options[:eval] = v
        end
        o.on("--memory-size=SIZE", Integer, "メモリサイズの指定(デフォルト:#{(Rasl.config.memory_size)})") do |v|
          Rasl.config.memory_size = v
        end
        o.on("--spec=NUMBER", Integer, "CASL1なら1を指定しとく。するとGR4がSPになる") do |v|
          Rasl.config.spec = v
        end
        o.on("--ds-init-value=VAL","DSで領域確保したときの初期値(デフォルト:#{Rasl.config.ds_init_value})") do |v|
          Rasl.config.ds_init_value = Integer(v)
        end
        o.on("--memory-defval=VAL", "メモリの初期値(デフォルト:#{Rasl.config.memory_defval})") do |v|
          Rasl.config.memory_defval = Integer(v)
        end
        o.on("--[no-]bol-order", "命令の前に空白を書かなくてよいことにする(デフォルト:#{Rasl.config.bol_order})") do |v|
          Rasl.config.bol_order = v
        end
        o.on("-i", "--register", "実行後にレジスタ一覧を表示する") do |v|
          @options[:register] = v
        end
      end
    end

    def execute(args)
      begin
        parser.parse!(args)
      rescue OptionParser::InvalidOption => error
        puts error
        usage
      end

      if File === ARGF.file
        @file = ARGF.file
      end

      @processor = Processor.new
      if @options[:eval]
        @processor.assemble(@options[:eval])
      else
        @processor.assemble(ARGF.read.toutf8)
      end

      if @file && @options[:output_map]
        @processor.create_map_file(file_name_of(:map))
      end

      if @options[:go]
        @processor.go
      end

      if @options[:print_map]
        puts @processor.disassemble
      end

      if @options[:register]
        puts @processor.regs_info
      end

      if @options[:simulator]
        @processor.simulator
      end
    end

    def usage
      puts "使い方: #{parser.program_name} [オプション] <ファイル>..."
      puts "`#{parser.program_name}' --help でより詳しい情報を表示します。"
      abort
    end

    def file_name_of(extname)
      Pathname("#{Pathname(@file).basename(".*")}.#{extname}")
    end
  end
end

if $0 == __FILE__
  Rasl.config.memory_size = 256
  object = Rasl::Processor.new
  object.assemble("RET")
  puts object.disassemble
  object.go
  p object.labels
  object.command_dump
end
