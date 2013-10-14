# -*- coding: utf-8 -*-
require "../lib/rasl"

app = Rasl::Processor.new
app.assemble <<-SOURCE
        OUT     STR, LEN
        RET
STR     DC      'Hello'
LEN     DC      5
SOURCE
puts app.disassemble
app.go
# >> 0000 7001 0000    PUSH    #0000, GR1
# >> 0002 7002 0000    PUSH    #0000, GR2
# >> 0004 1210 000D    LAD     GR1, #000D
# >> 0006 1220 0012    LAD     GR2, #0012
# >> 0008 F000 0001    SVC     #0001
# >> 000A 7120         POP     GR2
# >> 000B 7110         POP     GR1
# >> 000C 8100         RET
# >> 000D 0048         DC      72     ; 'H'
# >> 000E 0065         DC      101    ; 'e'
# >> 000F 006C         DC      108    ; 'l'
# >> 0010 006C         DC      108    ; 'l'
# >> 0011 006F         DC      111    ; 'o'
# >> 0012 0005         DC      5
# >> Hello
