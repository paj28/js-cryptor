package foo

fun findArrayInArray(needle: ByteArray, haystack: ByteArray): Boolean {
    val end = Integer.min(1024, haystack.size) - needle.size;
    val firstByte = needle[0]
    outer@ for (i in 0 .. end) {
            for (j in 0 .. needle.lastIndex) {
                if (haystack[i + j] != needle[j]) {
                    break@outer
                }
            }
            return true
    }
    return false
}

fun findArrayInArrayB(needle: ByteArray, haystack: ByteArray): Boolean {
    val end = Integer.min(1024, haystack.size) - needle.size;
    val firstByte = needle[0]
    outer@ for (i in 0 .. end) {
        if (haystack[i] == firstByte) {
            for (j in 1 .. needle.lastIndex) {
                if (haystack[i + j] != needle[j]) {
                    break@outer
                }
            }
            return true
        }
    }
    return false
}



fun main(args: Array<String>) {
    var a = ("\n" +
            "<p>To reduce database lookups, all services (including hub) use a stateless token in addition to the session token, called the <i>session pass</i>. It is cryptographically generated and can be verified without contacting the hub. Session passes can't be revoked so are time limited to 5 minutes.</p>\n" +
            "\n" +
            "<p>The token consists of: user ID, path, and timestamp. These values are combined into a string, then an HMAC is generated, using a master key. The master key is different between services, and shared between clustered machines in the same service. It is changed every 24 hours. No special process is needed for change; issued passes become invalid and are transparently reissued.</p>\n" +
            "\n" +
            "<p>If the session pass is invalid, the app verifies the session token and if valid, issues a new pass. This process is transparent to the user.</p>\n" +
            "\n" +
            "*** Is there any point? Memory cache is fine???\n" +
            "\thub returns all realms user authed for...\n" +
            "\tcould even do this as push, on login, logout,\n" +
            "\t\twould need a query on startup\n" +
            "\n" +
            "!!! Need to benchmark SQL [check it's not urandom at fault - no, it's not]\n" +
            "\tMariaDB - 35s for 10000 inserts\n" +
            "\t53s for 10000 reads\n" +
            "\t---> very poor :(\n" +
            "\n" +
            "\n").toByteArray(Charsets.ISO_8859_1)
    val b = "fdlkjsd".toByteArray(Charsets.ISO_8859_1)

    val q = System.currentTimeMillis()
    for (i in 0..100000000) {
        findArrayInArrayB(b, a)
    }
    println(System.currentTimeMillis() - q)

}