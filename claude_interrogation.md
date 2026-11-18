**Venus: When verifying, why load the saved `.hmac` file instead of recomputing the tag from the file and key?**

**Claude:** Recomputing would make verification always pass, hiding exactly the thing we want to detect: that the file changed since the tag was made. The test `test_hmac_does_not_recompute` writes a tag, edits the file, and expects `NOT VERIFIED`.

**Venus: Why loop on `recv` instead of one big read?**

**Claude:** TCP is a byte stream, so a single `recv` may return part of a message. `recv_exact` loops until it has the requested byte count and treats an empty read as premature EOF. The fake server has a `fragment` mode that sends the reply three bytes at a time, and the test passes only because of the loop.

**Venus: You validate `payload_len` carefully, including rejecting booleans. Why would a boolean come up?**

**Claude:** In Python `isinstance(True, int)` is true, so a naive check would accept `true` as length 1. The server is trusted-ish, but the client is supposed to validate before allocating anything, and a hostile or buggy reply shouldn't make us allocate or read an unexpected amount. Negative and over-1 MiB values are rejected for the same reason.

**Venus: The server gives one generic error for everything. How did you handle that honestly in the UI?**

**Claude:** The client shows the server's text unchanged and doesn't invent a reason. While you were testing, "error processing request" came back for `get_key`. From the client I could prove the same code succeeded with the username `vkanobay` and failed with `vkannobay`, which points to a username typo, but the server never says so. I presented that as the likely cause, not a fact the app can report.


