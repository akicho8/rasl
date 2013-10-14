# -*- coding: utf-8 -*-
require "../lib/rasl"

app = Rasl::Processor.new
app.assemble <<-SOURCE
MAIN    START
        LD      GR0,=1
        ADDA    GR0,=2
        ADDA    GR0,=3
        ST      GR0,RESULT
        RET
RESULT  DS      1
        END
SOURCE
app.go
app.memory[app.labels["MAIN"]["RESULT"]]     # => 6
puts app.disassemble
# >> 0000 1000 000A    LD      GR0, #000A
# >> 0002 2000 000B    ADDA    GR0, #000B
# >> 0004 2000 000C    ADDA    GR0, #000C
# >> 0006 1100 0009    ST      GR0, #0009
# >> 0008 8100         RET
# >> 0009 0006         DC      6
# >> 000A 0001         DC      1
# >> 000B 0002         DC      2
# >> 000C 0003         DC      3
