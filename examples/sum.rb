# -*- coding: utf-8 -*-
require "../lib/rasl"

app = Rasl::Processor.new
app.assemble <<-SOURCE
MAIN    START
        LD      GR0,=1
        LD      GR1,=2
        ADDA    GR0,GR1
        ST      GR0,RESULT
        RET
RESULT  DS      1
        END
SOURCE
app.go
app.gr[:gr0].value                       # => 3
app.labels["MAIN"]                       # => {"RESULT"=>8}
app.memory[app.labels["MAIN"]["RESULT"]] # => 3
puts app.disassemble
# >> 0000 1000 0009    LD      GR0, #0009
# >> 0002 1010 000A    LD      GR1, #000A
# >> 0004 2401         ADDA    GR0, GR1
# >> 0005 1100 0008    ST      GR0, #0008
# >> 0007 8100         RET
# >> 0008 0003         DC      3
# >> 0009 0001         DC      1
# >> 000A 0002         DC      2
