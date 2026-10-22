package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUpdateTest {
    @Test fun normalizeStripsPrefixAndSuffix() {
        assertEquals("1.2.0", AppUpdateLogic.normalize("v1.2.0"))
        assertEquals("1.2.0", AppUpdateLogic.normalize("V1.2.0-beta"))
        assertEquals("2.0", AppUpdateLogic.normalize("release-2.0"))
    }

    @Test fun isNewerComparesDottedVersions() {
        assertTrue(AppUpdateLogic.isNewer("1.2.0", "1.1.9"))
        assertTrue(AppUpdateLogic.isNewer("v1.10.0", "1.9.0"))   // 10 > 9, not string compare
        assertTrue(AppUpdateLogic.isNewer("1.1", "1.0.9"))
        assertFalse(AppUpdateLogic.isNewer("1.0.0", "1.0.0"))
        assertFalse(AppUpdateLogic.isNewer("1.0.0", "1.0.1"))
        assertFalse(AppUpdateLogic.isNewer("1.0", "1.0.0"))      // equal when padded
    }

    @Test fun parsePicksApkAssetAndNotes() {
        val json = """
            {"tag_name":"v1.3.0","html_url":"https://github.com/o/r/releases/tag/v1.3.0",
             "body":"Fixes and a new scanner.",
             "assets":[
               {"name":"mapping.txt","browser_download_url":"https://x/mapping.txt"},
               {"name":"sentinel-1.3.0.apk","browser_download_url":"https://x/sentinel.apk"}
             ]}
        """.trimIndent()
        val r = AppUpdateLogic.parse(json)!!
        assertEquals("1.3.0", r.versionName)
        assertEquals("https://x/sentinel.apk", r.apkUrl)
        assertTrue(r.notes.contains("new scanner"))
    }

    @Test fun parseSkipsDraftsAndPrereleases() {
        assertNull(AppUpdateLogic.parse("""{"tag_name":"v2.0.0","draft":true}"""))
        assertNull(AppUpdateLogic.parse("""{"tag_name":"v2.0.0","prerelease":true}"""))
    }

    @Test fun parseHandlesNoApkAsset() {
        val r = AppUpdateLogic.parse("""{"tag_name":"v1.4.0","assets":[]}""")!!
        assertEquals("1.4.0", r.versionName)
        assertNull(r.apkUrl)
    }

    @Test fun parseRejectsJunk() {
        assertNull(AppUpdateLogic.parse("not json"))
        assertNull(AppUpdateLogic.parse("""{"message":"Not Found"}"""))
    }
}
