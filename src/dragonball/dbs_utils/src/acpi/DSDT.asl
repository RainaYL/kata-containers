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
                Memory32Fixed (ReadWrite, 0x1E000000, 0x2000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {5}
            })
        }
    }
}