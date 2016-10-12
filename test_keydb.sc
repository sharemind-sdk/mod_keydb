import stdlib;
import keydb;
import shared3p_keydb;

domain pd_shared3p shared3p;

void main() {
    keydb_connect("host");
    scanDB("*");
    assert(keydb_clean("*"));
    string key = "key";
    uint16[[1]] b = {3,2,1};
    uint16 proxy;
    uint16[[1]] a = keydb_get(key, proxy);
    pd_shared3p xor_uint16[[1]] xor = {3,1,4,213};
    pd_shared3p xor_uint16 proxy1;
    pd_shared3p xor_uint16[[1]] xor_ret = keydb_get("asd", proxy1);
    keydb_set("asd", xor);
    pd_shared3p uint8 omg = 123;
    keydb_set("omg", omg);
    assert(declassify(all(xor == xor_ret)));
    keydb_disconnect();
}
