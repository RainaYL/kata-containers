DefinitionBlock ("DSDT.aml", "DSDT", 0x02, "DGBALL", "KATADBS ", 0x01)
{
    Scope (_SB)
    {
        Device (VCON)
        {
            Name (_HID, "LNRO0001")
            Name (_UID, 0)
            Name (_CRS, ResourceTemplate()
            {
                Memory32Fixed (ReadWrite, 0xE0000000, 0x2000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {5}
            })

            Method (_STA, 0, NotSerialized)
            {
                Return (0x0F)
            }
        }

        Device (BLK1)
        {
            Name (_HID, "LNRO0002")
            Name (_UID, 0)
            Name (_CRS, ResourceTemplate()
            {
                Memory32Fixed (ReadWrite, 0xE0002000, 0x2000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {5}
            })

            Method (_STA, 0, NotSerialized)
            {
                Return (0x0F)
            }
        }

        Device (BLK2)
        {
            Name (_HID, "LNRO0002")
            Name (_UID, 1)
            Name (_CRS, ResourceTemplate()
            {
                Memory32Fixed (ReadWrite, 0xE0004000, 0x2000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {5}
            })

            Method (_STA, 0, NotSerialized)
            {
                Return (0x0F)
            }
        }
    }
}