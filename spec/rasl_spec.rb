# -*- coding: utf-8 -*-

require "spec_helper"

describe Rasl do
  before do
    Rasl.configure do |config|
      config.memory_size   = 65536
      config.bol_order     = true
      config.ds_init_value = -1
    end

    @p = Processor.new
  end

  it "regs_info" do
    @p.regs_info.should == "GR0=0000 GR1=0000 GR2=0000 GR3=0000 GR4=0000 GR5=0000 GR6=0000 GR7=0000 PC=0000 SP=0000 FR=___(+)"
  end

  describe Value do
    it "符号の有無はアクセサによって決まる" do
      r = Value.new(-1)
      [r.value, r.s_value, r.u_value].should == [65535, -1, 65535]
      r = Value.new(65535)
      [r.value, r.s_value, r.u_value].should == [65535, -1, 65535]
    end
  end

  describe Register do
    it do
      r = Register.new(:ax, :pos => 0)
      r.key.should == :ax
      r.name.should == "AX"
      r.pos.should == 0
      r.to_s.should == "AX=0000"
    end
  end

  describe Env do
    it "new" do
      @p.code_size.should == 0
      @p.boot_pc.should == 0
      @p.gr[:sp].value == @p.memory.size
    end
  end

  describe OperandPresets1 do
    describe "基本命令" do
      it "nop" do
        asm " nop"
      end

      describe "ld" do
        it "r_imm" do
          asm "ld gr0, a", :dc => {:a => -77}
          reg_is :gr0, -77
          fire :sf
        end
        it "rix" do
          asm "ld gr0, a, gr1", :dc => {:a => [-444, -77]}, :regs => {:gr1 => 1}
          reg_is :gr0, -77
          fire :sf
        end
        it "r1_r2" do
          asm "ld gr1, gr0", :regs => {:gr0 => -77}
          reg_is :gr1, -77
          fire :sf
        end
      end

      describe "st" do
        it "r_imm" do
          asm "st gr0, a", :dc => {:a => 0}, :regs => {:gr0 => -77}
          var_check :a, -77
          fr_blank
        end
        it "rix" do
          asm "st gr0, a, gr1", :dc => {:a => 0, :b => 0}, :regs => {:gr0 => -77, :gr1 => 1}
          var_check :b, -77
          fr_blank
        end
      end

      describe "lea" do
        it "r_imm" do
          asm "lea gr0, -77"
          reg_is :gr0, -77
          fire :sf
        end
        it "rix" do
          asm "lea gr0, 1, gr1", :regs => {:gr1 => -77 - 1}
          reg_is :gr0, -77
          fire :sf
        end
      end

      describe "adda" do
        describe "r1_r2" do
          describe "上限" do
            it "of_true" do
              asm "adda gr0, gr1", :regs => {:gr0 => 1, :gr1 => 32767}
              reg_is :gr0, -32768
              fire :of, :sf
            end
            it "of_false" do
              asm "adda gr0, gr1", :regs => {:gr0 => 0, :gr1 => 32767}
              reg_is :gr0, 32767
              fire
            end
          end
          describe "下限" do
            it "of_true" do
              asm "adda gr0, gr1", :regs => {:gr0 => -1, :gr1 => -32768}
              reg_is :gr0, 32767
              fire :of
            end
            it "of_false" do
              asm "adda gr0, gr1", :regs => {:gr0 => 0, :gr1 => -32768}
              reg_is :gr0, -32768
              fire :sf
            end
          end
        end
        it "rix" do
          asm "adda gr0, a, gr1", :dc => {:a => 0, :b => -66}, :regs => {:gr0 => -11, :gr1 => 1}
          reg_is :gr0, -77
          fire :sf
        end
      end

      describe "addl" do
        describe "r1_r2" do
          describe "上限" do
            it "of_true" do
              asm "addl gr0, gr1", :regs => {:gr0 => 1, :gr1 => 65535}
              reg_is :gr0, 0
              fire :of, :zf
            end
            it "of_false" do
              asm "addl gr0, gr1", :regs => {:gr0 => 0, :gr1 => 65535}
              reg_is :gr0, -1
              fire :sf
            end
          end
          describe "下限" do
            it "of_false" do
              asm "addl gr0, gr1", :regs => {:gr0 => -1, :gr1 => 0}
              reg_is :gr0, -1
              fire :sf
            end
          end
        end
      end

      describe "alias" do
        it "add" do
          asm "add gr0, a, gr1", :dc => {:a => 0, :b => -66}, :regs => {:gr0 => -11, :gr1 => 1}
          reg_is :gr0, -77
          fire :sf
        end
        it "sub" do
          asm "sub gr0, a, gr1", :dc => {:a => 0, :b =>  88}, :regs => {:gr0 => 11, :gr1 => 1}
          reg_is :gr0, -77
          fire :sf
        end
        it "eor" do
          asm "eor gr0, a, gr1", :dc => {:a => 0, :b => 0x5500}, :regs => {:gr0 => 0xf0f0, :gr1 => 1}
          @p.gr[:gr0].value.should == 0xa5f0
          fire :sf
        end
      end

      describe "論理演算" do
        describe "r1_r2" do
          it do
            logic_check(:and, 0x5000)
            logic_check(:or,  0xf5f0)
            logic_check(:xor, 0xa5f0)
          end

          def logic_check(order, result)
            asm "#{order} gr0, gr1", :regs => {:gr0 => 0xf0f0, :gr1 => 0x5500}
            @p.gr[:gr0].value.should == result
          end
        end

        describe "rix" do
          it "xor" do
            asm "xor gr0, a, gr1", :dc => {:a => 0, :b => 0x5500}, :regs => {:gr0 => 0xf0f0, :gr1 => 1}
            @p.gr[:gr0].value.should == 0xa5f0
            fire :sf
          end
        end
      end

      it "比較" do
        compare_check(:cpa,  1, -1, [])
        compare_check(:cpl,  1, -1, [:sf])
        compare_check(:cpa, -1,  1, [:sf])
        compare_check(:cpl, -1,  1, [])
      end

      def compare_check(order, a, b, flags)
        @p.init_env
        asm ["lea gr0, #{a}", "#{order} gr0, a"], :dc => {:a => b}
        fire *flags
      end

      describe "シフト" do
        it do
          shift_check :sla, -1, 0b1000000000000000, [:of, :sf]
          shift_check :sla,  0, 0b1010000000000001, [:sf]
          shift_check :sla,  1, 0b1100000000000010, [:of, :sf]
          shift_check :sla,  2, 0b1000000000000100, [:of, :sf]
          shift_check :sla, 15, 0b1000000000000000, [:of, :sf]
          shift_check :sla, 16, 0b1000000000000000, [:of, :sf]
          shift_check :sla, 17, 0b1000000000000000, [:of, :sf]
          shift_check :sla, 64, 0b1000000000000000, [:of, :sf]
          shift_check :sra, -1, 0b1111111111111111, [:of, :sf]
          shift_check :sra,  0, 0b1010000000000001, [:sf]
          shift_check :sra,  1, 0b1101000000000000, [:of, :sf]
          shift_check :sra,  2, 0b1110100000000000, [:sf]
          shift_check :sra, 15, 0b1111111111111111, [:sf]
          shift_check :sra, 16, 0b1111111111111111, [:of, :sf]
          shift_check :sra, 17, 0b1111111111111111, [:of, :sf]
          shift_check :sra, 64, 0b1111111111111111, [:of, :sf]
          shift_check :sll, -1, 0b0000000000000000, [:of, :zf]
          shift_check :sll,  0, 0b1010000000000001, [:sf]
          shift_check :sll,  1, 0b0100000000000010, [:of]
          shift_check :sll,  2, 0b1000000000000100, [:sf]
          shift_check :sll, 15, 0b1000000000000000, [:sf]
          shift_check :sll, 16, 0b0000000000000000, [:of, :zf]
          shift_check :sll, 17, 0b0000000000000000, [:of, :zf]
          shift_check :sll, 64, 0b0000000000000000, [:of, :zf]
          shift_check :srl, -1, 0b0000000000000000, [:of, :zf]
          shift_check :srl,  0, 0b1010000000000001, [:sf]
          shift_check :srl,  1, 0b0101000000000000, [:of]
          shift_check :srl,  2, 0b0010100000000000, []
          shift_check :srl, 15, 0b0000000000000001, []
          shift_check :srl, 16, 0b0000000000000000, [:of, :zf]
          shift_check :srl, 17, 0b0000000000000000, [:of, :zf]
          shift_check :srl, 64, 0b0000000000000000, [:of, :zf]
        end

        def shift_check(order, count, result_value, result_flgs)
          @p.init_env
          asm "#{order} gr0, count", :dc => {:count => count}, :regs => {:gr0 => 0b1010000000000001}
          # p(["%016b" % @p.gr[:gr0].value, @p.gr[:fr].available_flags])
          # [@p.gr[:gr0].value, @p.gr[:fr].available_flags]
          @p.gr[:gr0].value.should == result_value
          fire *result_flgs
        end
      end

      describe "jmp" do
        it do
          jmp_check :jmp,  [1, 1, 1]
          jmp_check :jump, [1, 1, 1]
          jmp_check :jpl,  [0, 0, 1]
          jmp_check :jpz,  [0, 1, 1]
          jmp_check :jmi,  [1, 0, 0]
          jmp_check :jnz,  [1, 0, 1]
          jmp_check :jze,  [0, 1, 0]
        end

        def jmp_check(order, result)
          [].tap do |gr0|
            @p.init_env; asm ["lea gr0, -1", "#{order} a", "lea gr0, 0", "jmp b", "a lea gr0, 1", "b nop"]; gr0 << @p.gr[:gr0].s_value
            @p.init_env; asm ["lea gr0,  0", "#{order} a", "lea gr0, 0", "jmp b", "a lea gr0, 1", "b nop"]; gr0 << @p.gr[:gr0].s_value
            @p.init_env; asm ["lea gr0,  1", "#{order} a", "lea gr0, 0", "jmp b", "a lea gr0, 1", "b nop"]; gr0 << @p.gr[:gr0].s_value
          end.should == result
        end
      end

      describe "jov" do
        it "of_true" do
          asm ["jov a", "jmp e", "a lea gr0, 77", "e nop"], :flags => {:of => true}
          reg_is :gr0, 77
        end
        it "of_false" do
          asm ["jov a", "jmp e", "a lea gr0, 77", "e nop"], :flags => {:of => false}
          reg_is :gr0, 0
        end
      end

      it "push_pop" do
        asm ["push 77", "pop gr0"]
        reg_is :gr0, 77
      end

      it "call" do
        asm ["call a", "a nop"]
        @p.memory[@p.gr[:sp].value].should == 2
      end

      describe "ret" do
        it do
          asm ["call a", "lea gr1,77", "jmp e", "a lea gr0,77", "ret", "e nop"]
          reg_is :gr0, 77
          reg_is :gr1, 77
        end

        it "ret で正常に戻ったかどうかは exit_key でわかる" do
          asm "RET"
          @p.exit_key.should == :ret
        end
      end
    end

    describe "擬似命令" do
      it "start" do
        asm [" start a", " lea gr0, 444", " jmp e", "a lea gr0, 77", "e nop"]
        reg_is :gr0, 77
      end

      # it "end" do
      #   @p.assemble(["start", "ld gr0,=77", " dc 0", "end"].join("\n"))
      #   @p.memory[@p.code_size - 1].should == 77
      # end
      #
      # it "ds" do
      #   @p.assemble [" nop", "a ds a"].join("\n") # 個数がラベル
      #   @p.code_size.should == 2
      #
      #   @p.assemble " ds 7"
      #   @p.code_size.should == 7
      #
      #   @p.assemble " ds 0"
      #   @p.code_size.should == 0
      # end
      #
      # describe "dc" do
      #   it do
      #     dc_check %{''}, ""
      #     dc_check %{'\;'}, ";"
      #     dc_check %{'a'}, "a"
      #     dc_check %{"a"}, "a"
      #     dc_check %{10}, "\x0a"
      #     dc_check %{'a', 'b', 0, 'c', 'd'}, "ab\x00cd"
      #     dc_check %{'a''b''c',0,'d''e''f'}, "a'b'c\x00d'e'f"
      #     dc_check %{"a""b""c",0,'d''e''f'}, %{a"b"c\x00d'e'f}
      #   end
      #
      #   it "ラベルはアドレスに展開" do
      #     asm ["nop", "a nop"], :dc => {:b => :a}
      #     var_check :b, @p.labels[:a]
      #   end
      #
      #   def dc_check(code, result)
      #     @p.assemble " dc #{code}"
      #     @p.memory[0...@p.code_size].pack("C*").should == result
      #   end
      # end
    end

    describe "マクロ" do
      describe "in" do
        shared_examples_for "test" do
          it do
            asm "in buf,len", :ds => {:buf => 4}, :dc => {:len => 0}
            @p.memory[@p.labels[:__global__]["buf"] + 0].should == "a".ord
            @p.memory[@p.labels[:__global__]["buf"] + 1].should == "b".ord
            var_check :len, 2
          end
        end

        describe "@dataから" do
          before { @p.data = ["ab"] }
          it_behaves_like "test"
        end

        describe "標準入力" do
          before do
            @save_stdin = $stdin
            $stdin = double("stdin", :gets => "ab")
          end
          after do
            $stdin = @save_stdin
          end
          it_behaves_like "test"
        end
      end

      it "out" do
        capture(:stdout) {
          asm ["out str,len", "out str,len"], :dc => {:str => "'abcd'", :len => 2}
        }.should == "ab\nab\n"
      end

      it "exit" do
        asm
      end

      it "rpush rpop" do
        asm ["lea gr1, 77", "rpush", "lea gr1, 444", "rpop"]
        reg_is :gr1, 77
      end
    end
  end

  describe Parser do
    it "ラベル" do
      @p.assemble("foo").labels.should  == {:__global__ => {"foo" => 0}}
      @p.assemble("foo:").labels.should == {:__global__ => {"foo" => 0}}
      @p.assemble("Foo:").labels.should == {:__global__ => {"Foo" => 0}}
      @p.assemble("lad:").labels.should == {:__global__ => {"lad" => 0}}
      @p.assemble("@xx").labels.should  == {:__global__ => {"@xx" => 0}}
      @p.assemble("$xx").labels.should  == {:__global__ => {"$xx" => 0}}
    end

    it "コメント" do
      @p.assemble(" DC #77 ; comment").disassemble.should match "77"
      @p.assemble("#DC #77").code_size.should == 0
      @p.assemble(";DC #77").code_size.should == 0
    end

    it "インラインデータ" do
      @p.assemble([" ld gr1, =1", " nop"].join("\n"))
      @p.disassemble.should == <<-EOT
0000 1010 0003    LD      GR1, #0003
0002 0900         NOP
0003 0001         DC      1
EOT
      @p.assemble([" dc ='abcd'", " nop"].join("\n"))
      @p.disassemble.should == <<-EOT
0000 0002         DC      2
0001 0900         NOP
0002 0061         DC      97     ; 'a'
0003 0062         DC      98     ; 'b'
0004 0063         DC      99     ; 'c'
0005 0064         DC      100    ; 'd'
EOT
    end

    it "即値" do
      value_format_check "010",  8
      value_format_check "10",  10
      value_format_check "#10", 0x10
      value_format_check "0x10", 0x10
      value_format_check "0b10", 2
    end

    def value_format_check(str, result)
      @p.assemble(" DC #{str}")
      @p.memory.first.should == result
    end
  end

  describe RaslError do
    before do
      @bol_order = Rasl.config.bol_order
    end
    after do
      Rasl.config.bol_order = @bol_order
    end

    it do
      Rasl.config.bol_order = false; expect { @p.assemble "JPZ GR1, 1, GR2" }.to raise_error(InvalidOrder)
      Rasl.config.bol_order = true;  expect { @p.assemble "JPZ GR1, 1, GR2" }.to raise_error(LabelNotFound)
    end

    it do
      expect { asm "JPZ GR1, 1, GR2" }.to raise_error(LabelNotFound)
    end
  end

  describe Simulator do
    describe "r" do
      it "r" do
        @p.command_init
        capture(:stdout) { @p.post_command("r") }.should == <<-EOT
GR0=0000 GR1=0000 GR2=0000 GR3=0000 GR4=0000 GR5=0000 GR6=0000 GR7=0000 PC=0000 SP=FFFF FR=___(+)
0000 0000         DC      0
EOT
      end

      it "rGR=77" do
        @p.command_init
        @p.post_command("rGR0=77")
        @p.gr[:gr0].value.should == 77
      end

      it "asm => r" do
        asm "lea GR0,1"
        capture(:stdout) { @p.post_command("r") }.should == <<-EOT
GR0=0001 GR1=0000 GR2=0000 GR3=0000 GR4=0000 GR5=0000 GR6=0000 GR7=0000 PC=0004 SP=FFFF FR=___(+) [exit]
0004 0000         DC      0
EOT
      end
    end

    it "#disassemble" do
      @p.assemble("ld gr0, 1").disassemble.should == "0000 1000 0001    LD      GR0, #0001\n"
    end
  end

  it "disassemble" do
    @p.assemble <<-SOURCE
   NOP
   LD   GR1, 1, GR2
   ST   GR1, 1, GR2
   LAD  GR1, 1, GR2
   LD   GR1, GR2
   ADDA GR1, 1, GR2
   SUBA GR1, 1, GR2
   ADDA GR3, GR4
   SUBA GR3, GR4
   AND  GR1, 1, GR2
   OR   GR1, 1, GR2
   XOR  GR1, 1, GR2
   AND  GR1, GR2
   OR   GR1, GR2
   XOR  GR1, GR2

   CPA  GR1, 1, GR2
   CPL  GR1, 1, GR2
   CPA  GR1, GR2
   CPL  GR1, GR2

   SLA  GR1, 1, GR2
   SRA  GR1, 1, GR2
   SLL  GR1, 1, GR2
   SRL  GR1, 1, GR2

   JPZ  1, GR2
   JMI  1, GR2
   JNZ  1, GR2
   JZE  1, GR2
   JUMP 1, GR2
   JPL  1, GR2
   JOV  1, GR2

   PUSH #0077, GR2
   POP  GR0
   CALL #0077, GR2
   RET

   RPUSH
   RPOP

   IN    1, 2
   OUT   3, 4
   SVC   0, GR2
   EXIT

   JMP  A
   EOR  GR0, A
   ADD  GR1, 1, GR2
   SUB  GR1, 1, GR2

A DC 'a''b','c'
B DS 0
C DS 3
SOURCE
    @p.disassemble.should == <<-MAP
0000 0900         NOP
0001 1012 0001    LD      GR1, #0001, GR2
0003 1112 0001    ST      GR1, #0001, GR2
0005 1212 0001    LAD     GR1, #0001, GR2
0007 1412         LD      GR1, GR2
0008 2012 0001    ADDA    GR1, #0001, GR2
000A 2112 0001    SUBA    GR1, #0001, GR2
000C 2434         ADDA    GR3, GR4
000D 2534         SUBA    GR3, GR4
000E 3012 0001    AND     GR1, #0001, GR2
0010 3112 0001    OR      GR1, #0001, GR2
0012 3212 0001    XOR     GR1, #0001, GR2
0014 3412         AND     GR1, GR2
0015 3512         OR      GR1, GR2
0016 3612         XOR     GR1, GR2
0017 4012 0001    CPA     GR1, #0001, GR2
0019 4112 0001    CPL     GR1, #0001, GR2
001B 4412         CPA     GR1, GR2
001C 4512         CPL     GR1, GR2
001D 5012 0001    SLA     GR1, #0001, GR2
001F 5112 0001    SRA     GR1, #0001, GR2
0021 5212 0001    SLL     GR1, #0001, GR2
0023 5312 0001    SRL     GR1, #0001, GR2
0025 6002 0001    JPZ     #0001, GR2
0027 6102 0001    JMI     #0001, GR2
0029 6202 0001    JNZ     #0001, GR2
002B 6302 0001    JZE     #0001, GR2
002D 6402 0001    JUMP    #0001, GR2
002F 6502 0001    JPL     #0001, GR2
0031 6602 0001    JOV     #0001, GR2
0033 7002 0077    PUSH    #0077, GR2
0035 7100         POP     GR0
0036 8002 0077    CALL    #0077, GR2
0038 8100         RET
0039 7001 0000    PUSH    #0000, GR1
003B 7002 0000    PUSH    #0000, GR2
003D 7003 0000    PUSH    #0000, GR3
003F 7004 0000    PUSH    #0000, GR4
0041 7005 0000    PUSH    #0000, GR5
0043 7006 0000    PUSH    #0000, GR6
0045 7007 0000    PUSH    #0000, GR7
0047 7170         POP     GR7
0048 7160         POP     GR6
0049 7150         POP     GR5
004A 7140         POP     GR4
004B 7130         POP     GR3
004C 7120         POP     GR2
004D 7110         POP     GR1
004E 7001 0000    PUSH    #0000, GR1
0050 7002 0000    PUSH    #0000, GR2
0052 1210 0001    LAD     GR1, #0001
0054 1220 0002    LAD     GR2, #0002
0056 F000 0000    SVC     #0000
0058 7120         POP     GR2
0059 7110         POP     GR1
005A 7001 0000    PUSH    #0000, GR1
005C 7002 0000    PUSH    #0000, GR2
005E 1210 0003    LAD     GR1, #0003
0060 1220 0004    LAD     GR2, #0004
0062 F000 0001    SVC     #0001
0064 7120         POP     GR2
0065 7110         POP     GR1
0066 F002 0000    SVC     #0000, GR2
0068 F000 0002    SVC     #0002
006A 6400 0072    JUMP    #0072
006C 3200 0072    XOR     GR0, #0072
006E 2012 0001    ADDA    GR1, #0001, GR2
0070 2112 0001    SUBA    GR1, #0001, GR2
0072 0061         DC      97     ; 'a'
0073 0027         DC      39     ; '''
0074 0062         DC      98     ; 'b'
0075 0063         DC      99     ; 'c'
0076 FFFF         DC      -1
0077 FFFF         DC      -1
0078 FFFF         DC      -1
MAP
  end

  private

  def asm(order = nil, options = {})
    options = {
      :regs  => {},
      :flags => {},
      :dc    => {},
      :ds    => {},
    }.merge(options)

    options[:flags].each{|k, v|@p.gr[:fr].send("#{k}=", v)}
    options[:regs].each{|k, v|@p.gr[k].value = v}

    source = Array(order) + [" exit"]
    source += options[:dc].collect{|k, v|"#{k} dc #{Array(v).join(',')}"}
    source += options[:ds].collect{|k, v|"#{k} ds #{Array(v).join(',')}"}
    source = source.join("\n")

    @p.assemble_without_init_env(source)
    @p.before_go
    @p.command_go
    @p
  end

  def var_check(name, value)
    var(name).should == value
  end

  def var(name)
    Value.new(@p.memory[@p.labels[:__global__].fetch(name.to_s)]).s_value
  end

  def reg_is(name, value)
    @p.gr[name].s_value.should == value
  end

  def fire(*args)
    @p.gr[:fr].available_flags.should == args
  end

  def fr_blank
    fire
  end
end
