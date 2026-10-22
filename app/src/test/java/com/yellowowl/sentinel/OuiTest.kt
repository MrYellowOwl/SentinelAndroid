package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OuiTest {
    @Test
    fun normalizesCommonFormats() {
        assertEquals("b8:27:eb:11:22:33", Oui.normalize("B8-27-EB-11-22-33"))
        assertEquals("b8:27:eb:11:22:33", Oui.normalize("b827.eb11.2233"))
        assertEquals("b8:27:eb:11:22:33", Oui.normalize("b8:27:eb:11:22:33"))
        assertNull(Oui.normalize("not-a-mac"))
        assertNull(Oui.normalize("b8:27:eb:11:22")) // too short
    }

    @Test
    fun looksUpKnownVendors() {
        assertEquals("Raspberry Pi", Oui.vendor("b8:27:eb:aa:bb:cc"))
        assertEquals("Espressif (ESP)", Oui.vendor("24:0A:C4:00:11:22"))
        assertEquals("TP-Link", Oui.vendor("50:c7:bf:de:ad:be"))
        assertEquals("Apple", Oui.vendor("a4:83:e7:00:00:01"))
    }

    @Test
    fun unknownPrefixReturnsNull() {
        assertNull(Oui.vendor("08:11:22:33:44:55"))
    }

    @Test
    fun detectsRandomizedMac() {
        // 2nd-least-significant bit of first octet set => locally administered (e.g. 0x02, 0x06, 0x0a, 0xda)
        assertTrue(Oui.isLocallyAdministered("da:a1:19:00:11:22"))
        assertEquals("Randomized MAC", Oui.vendor("da:11:22:33:44:55"))
        assertTrue(!Oui.isLocallyAdministered("b8:27:eb:11:22:33"))
    }
}
