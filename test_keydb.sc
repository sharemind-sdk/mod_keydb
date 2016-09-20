import stdlib;

void keydb_connect() {
    __syscall ("keydb_connect");
}

void keydb_disconnect() {
    __syscall ("keydb_disconnect");
}

template <type T>
T[[1]] keydb_get(string key) {
    T dummy;
    uint num_bytes;
    uint obj;
    uint t_size = sizeof(dummy);
    __syscall("keydb_get_size", __ref obj, __cref key, __return num_bytes);
    T[[1]] out(num_bytes / t_size);
    __syscall("keydb_get", __cref obj, __ref out);
    return out;
}

template <type T>
void keydb_set(string key, T[[1]] value) {
    __syscall("keydb_set", __cref key, __cref value);
}

void main() {
    keydb_connect();
    string key = "key";
    uint16[[1]] b = {3,2,1};
    uint16[[1]] a = keydb_get(key);
    publish("a", a);
    keydb_set(key, {1,2,3});
    a = keydb_get(key);
    publish("a2", keydb_get(key));
    keydb_set(key, b);
    keydb_disconnect();
}
