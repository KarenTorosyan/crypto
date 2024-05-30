package util;

import javax.security.auth.x500.X500Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class X500PrincipalBuilder {

    private final Map<String, Object> attributes = new HashMap<>();

    public X500PrincipalBuilder attr(String name, String value) {
        attributes.put(name, value);
        return this;
    }

    public X500PrincipalBuilder cn(String cn) {
        return attr("CN", cn);
    }

    public X500PrincipalBuilder o(String o) {
        return attr("O", o);
    }

    public X500PrincipalBuilder ou(String ou) {
        return attr("OU", ou);
    }

    public X500PrincipalBuilder l(String l) {
        return attr("L", l);
    }

    public X500PrincipalBuilder st(String st) {
        return attr("ST", st);
    }

    public X500PrincipalBuilder c(String c) {
        return attr("C", c);
    }

    public X500PrincipalBuilder email(String email) {
        return attr("EMAIL", email);
    }

    public X500Principal build() {
        List<String> attributes = this.attributes.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .toList();
        return new X500Principal(String.join(", ", attributes));
    }
}
