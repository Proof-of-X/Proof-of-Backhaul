import "dart:typed_data";

enum MessageType
{
    CHALLENGE_PACKET
}

final MESSAGE_TYPE_CHALLENGE_PACKET = MessageType.CHALLENGE_PACKET.index;

bool is_string(final Map m, final String k)
{
    if (m.containsKey(k) && m[k] is String)
        return true;
    else
        return false;
}

bool is_double (final Map m, final String k)
{
    if (m.containsKey(k) && m[k] is double)
        return true;
    else
        return false;
}

bool is_bool(final Map m, final String k)
{
    if (m.containsKey(k) && m[k] is bool)
        return true;
    else
        return false;
}

bool is_list_equals (final List<int> a, final List<int> b)
{
    if (identical(a,b))
        return true;

    final length = a.length;

    if (length != b.length)
        return false;

    for (int i = 0; i < length; i++)
    {
        if (a[i] != b[i])
            return false;
    }

    return true;
}

String process_ip (final String ip)
{
    if (ip.startsWith("::ffff:") && ip.contains("."))
        return ip.split("::ffff:")[1];
    else
        return ip;
}

Uint8List int32bytes (int value)
{
    return Uint8List(4)..buffer.asUint32List()[0] = value;
}

Uint8List int8bytes (int value)
{
    return Uint8List(1)..buffer.asUint8List()[0] = value;
}
