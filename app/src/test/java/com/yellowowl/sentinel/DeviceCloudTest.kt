package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeviceCloudTest {
    @Test
    fun macVendorParsesCompanyWhenFound() {
        val json = """{"success":true,"found":true,"macPrefix":"A4:50:46","company":"Samsung Electronics"}"""
        assertEquals("Samsung Electronics", DeviceCloud.parseMacVendor(json))
    }

    @Test
    fun macVendorNullWhenNotFoundOrUnsuccessful() {
        assertNull(DeviceCloud.parseMacVendor("""{"success":true,"found":false}"""))
        assertNull(DeviceCloud.parseMacVendor("""{"success":false,"error":"rate limit"}"""))
        assertNull(DeviceCloud.parseMacVendor("not json"))
    }

    @Test
    fun fingerbankKeepsLeafAsModelAndClassifies() {
        val id = DeviceCloud.parseFingerbank("""{"device":{"name":"Apple/iPhone"},"score":90}""")!!
        assertEquals("iPhone", id.model)
        assertEquals("Phone", id.kind)
    }

    @Test
    fun fingerbankClassifiesConsoleAndTv() {
        assertEquals("Game console", DeviceCloud.parseFingerbank("""{"device":{"name":"Microsoft/Xbox"}}""")!!.kind)
        assertEquals("TV / media", DeviceCloud.parseFingerbank("""{"device":{"name":"Roku/Streaming Player"}}""")!!.kind)
    }

    @Test
    fun fingerbankNullOnMissingDevice() {
        assertNull(DeviceCloud.parseFingerbank("""{"score":10}"""))
        assertNull(DeviceCloud.parseFingerbank("garbage"))
    }
}
