require "../lib/rasl"

app = Rasl::Processor.new
app.assemble <<-SOURCE
; Hello, world.
MAIN    START
        OUT     STR, LEN
        RET
STR     DC      'Hello, world.'
LEN     DC      13
SOURCE
puts app.disassemble
app.go
app.code_dump
# >> 0000 7001 0000    PUSH    #0000, GR1
# >> 0002 7002 0000    PUSH    #0000, GR2
# >> 0004 1210 000D    LAD     GR1, #000D
# >> 0006 1220 001A    LAD     GR2, #001A
# >> 0008 F000 0001    SVC     #0001
# >> 000A 7120         POP     GR2
# >> 000B 7110         POP     GR1
# >> 000C 8100         RET
# >> 000D 0048         DC      72     ; 'H'
# >> 000E 0065         DC      101    ; 'e'
# >> 000F 006C         DC      108    ; 'l'
# >> 0010 006C         DC      108    ; 'l'
# >> 0011 006F         DC      111    ; 'o'
# >> 0012 002C         DC      44     ; ','
# >> 0013 0020         DC      32     ; ' '
# >> 0014 0077         DC      119    ; 'w'
# >> 0015 006F         DC      111    ; 'o'
# >> 0016 0072         DC      114    ; 'r'
# >> 0017 006C         DC      108    ; 'l'
# >> 0018 0064         DC      100    ; 'd'
# >> 0019 002E         DC      46     ; '.'
# >> 001A 000D         DC      13
# >> Hello, world.
# >> 0000: 7001 0000 7002 0000 1210 000D 1220 001A ........
# >> 0008: F000 0001 7120 7110 8100 0048 0065 006C .....Hel
# >> 0010: 006C 006F 002C 0020 0077 006F 0072 006C lo, worl
# >> 0018: 0064 002E 000D                          d..
