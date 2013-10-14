# -*- coding: utf-8 -*-
require "../lib/rasl"

app = Rasl::Processor.new
app.assemble <<-SOURCE
;; CASL - Wikipedia
;; http://ja.wikipedia.org/wiki/CASL
;; ハノイの塔を解くプログラム
MAIN   START
       LD      GR0,N
       LD      GR1,A
       LD      GR2,B
       LD      GR3,C
       CALL    HANOI
       RET

; hanoi(N, X, Y, Z)
HANOI  CPA     GR0,=1
       JZE     DISP
       SUBA    GR0,=1
       PUSH    0,GR2
       LD      GR2,GR3
       POP     GR3
       CALL    HANOI
       ST      GR1,MSG1
       ST      GR2,MSG2
       OUT     MSG,LNG
       PUSH    0,GR2
       LD      GR2,GR1
       LD      GR1,GR3
       POP     GR3
       CALL    HANOI
       PUSH    0,GR2
       LD      GR2,GR1
       POP     GR1
       ADDA    GR0,=1
       RET

DISP   ST      GR1,MSG1
       ST      GR3,MSG2
       OUT     MSG,LNG
       RET

N      DC      3
LNG    DC      11
A      DC      'A'
B      DC      'B'
C      DC      'C'
MSG    DC      'from '
MSG1   DS      1
       DC      ' to '
MSG2   DS      1
       END
SOURCE
puts app.disassemble
app.go
# >> 0000 1000 0046    LD      GR0, #0046
# >> 0002 1010 0048    LD      GR1, #0048
# >> 0004 1020 0049    LD      GR2, #0049
# >> 0006 1030 004A    LD      GR3, #004A
# >> 0008 8000 000B    CALL    #000B
# >> 000A 8100         RET
# >> 000B 4000 0056    CPA     GR0, #0056
# >> 000D 6300 0035    JZE     #0035
# >> 000F 2100 0057    SUBA    GR0, #0057
# >> 0011 7002 0000    PUSH    #0000, GR2
# >> 0013 1423         LD      GR2, GR3
# >> 0014 7130         POP     GR3
# >> 0015 8000 000B    CALL    #000B
# >> 0017 1110 0050    ST      GR1, #0050
# >> 0019 1120 0055    ST      GR2, #0055
# >> 001B 7001 0000    PUSH    #0000, GR1
# >> 001D 7002 0000    PUSH    #0000, GR2
# >> 001F 1210 004B    LAD     GR1, #004B
# >> 0021 1220 0047    LAD     GR2, #0047
# >> 0023 F000 0001    SVC     #0001
# >> 0025 7120         POP     GR2
# >> 0026 7110         POP     GR1
# >> 0027 7002 0000    PUSH    #0000, GR2
# >> 0029 1421         LD      GR2, GR1
# >> 002A 1413         LD      GR1, GR3
# >> 002B 7130         POP     GR3
# >> 002C 8000 000B    CALL    #000B
# >> 002E 7002 0000    PUSH    #0000, GR2
# >> 0030 1421         LD      GR2, GR1
# >> 0031 7110         POP     GR1
# >> 0032 2000 0058    ADDA    GR0, #0058
# >> 0034 8100         RET
# >> 0035 1110 0050    ST      GR1, #0050
# >> 0037 1130 0055    ST      GR3, #0055
# >> 0039 7001 0000    PUSH    #0000, GR1
# >> 003B 7002 0000    PUSH    #0000, GR2
# >> 003D 1210 004B    LAD     GR1, #004B
# >> 003F 1220 0047    LAD     GR2, #0047
# >> 0041 F000 0001    SVC     #0001
# >> 0043 7120         POP     GR2
# >> 0044 7110         POP     GR1
# >> 0045 8100         RET
# >> 0046 0003         DC      3
# >> 0047 000B         DC      11
# >> 0048 0041         DC      65     ; 'A'
# >> 0049 0042         DC      66     ; 'B'
# >> 004A 0043         DC      67     ; 'C'
# >> 004B 0066         DC      102    ; 'f'
# >> 004C 0072         DC      114    ; 'r'
# >> 004D 006F         DC      111    ; 'o'
# >> 004E 006D         DC      109    ; 'm'
# >> 004F 0020         DC      32     ; ' '
# >> 0050 0000         DC      0
# >> 0051 0020         DC      32     ; ' '
# >> 0052 0074         DC      116    ; 't'
# >> 0053 006F         DC      111    ; 'o'
# >> 0054 0020         DC      32     ; ' '
# >> 0055 0000         DC      0
# >> 0056 0001         DC      1
# >> 0057 0001         DC      1
# >> 0058 0001         DC      1
# >> from A to C
# >> from A to B
# >> from C to B
# >> from A to C
# >> from B to A
# >> from B to C
# >> from A to C
