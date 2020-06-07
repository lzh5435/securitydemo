package test.liuzehua.securitydemo.model;import lombok.Data;import lombok.experimental.Accessors;import org.springframework.security.core.GrantedAuthority;import org.springframework.security.core.authority.SimpleGrantedAuthority;import org.springframework.security.core.userdetails.UserDetails;import java.util.ArrayList;import java.util.Collection;import java.util.List;import static java.util.stream.Collectors.toList;/** * @author liuzehua * 2020/5/20 **/@Data@Accessors(chain = true)public class User implements UserDetails {    private int id;    private String username;    private String password;    private List<String> roles = new ArrayList<>();    /**     * 权限 集和     * @return     */    @Override    public Collection<? extends GrantedAuthority> getAuthorities() {        return this.roles.stream().map(SimpleGrantedAuthority::new).collect(toList());    }    @Override    public String getPassword() {        return password;    }    @Override    public String getUsername() {        return username;    }    /**     * 帐户是否未过期     * @return     */    @Override    public boolean isAccountNonExpired() {        return true;    }    /**     *帐户是否未锁定     * @return     */    @Override    public boolean isAccountNonLocked() {        return true;    }    /**     * 凭证是否未过期     * @return     */    @Override    public boolean isCredentialsNonExpired() {        return true;    }    /**     * 是否启用     * @return     */    @Override    public boolean isEnabled() {        return true;    }}