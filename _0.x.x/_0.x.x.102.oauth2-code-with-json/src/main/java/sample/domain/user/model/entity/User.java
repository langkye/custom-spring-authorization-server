package sample.domain.user.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import sample.config.provider.AuthType;
import sample.domain.login.model.entity.UserLogin;
import sample.domain.role.model.entity.Role;

import javax.persistence.*;
import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Entity
@Table(name = "system_user")
public class User implements UserDetails, Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    //@JsonIgnore
    //@Column(name = "password")
    //private String password;
    @Column(name = "username")
    private String username;
    @Column(name = "account_non_expired")
    boolean accountNonExpired = true;
    @Column(name = "account_non_locked")
    boolean accountNonLocked = true;
    //@Column(name = "credentials_non_expired")
    //boolean credentialsNonExpired = true;
    @Column(name = "is_enabled")
    Boolean isEnabled = true;
    @Column(name = "telephone")
    private String telephone;
    
    @JsonIgnore
    @ManyToMany(fetch = FetchType.EAGER)
    //@Fetch(FetchMode.JOIN)
    @Fetch(FetchMode.SELECT)
    @JoinTable(name = "system_user_role", joinColumns = {
            @JoinColumn(name = "user_id", referencedColumnName = "id") }, inverseJoinColumns = {
            @JoinColumn(name = "role_id", referencedColumnName = "id") })
    @org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
    @BatchSize(size = 20)
    //private Set<Role> roles = new HashSet<>();
    private List<Role> roles = new ArrayList<>();

    @Fetch(FetchMode.JOIN)
    @BatchSize(size = 20)
    @org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonManagedReference
    //@JsonIgnore
    //private Set<UserLogin> userLogins = new HashSet<>();
    private List<UserLogin> userLogins = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        //private Collection<GrantedAuthority> authorities;
        //return authorities;
        return roles.stream()
                .flatMap(role -> Stream.concat(
                        Stream.of(new SimpleGrantedAuthority(role.getName())),
                        role.getPermissions().stream()))
                .collect(Collectors.toSet());
    }

    //public void setAuthorities(Collection<GrantedAuthority> authorities) {
    //    this.authorities = authorities;
    //}

    @Override
    @JsonIgnore
    public String getPassword() {
        if (!CollectionUtils.isEmpty(userLogins)) {
            Optional<UserLogin> userLoginOptional = userLogins.stream().filter(it -> Objects.equals(it.getIdentity(), AuthType.password.getType().toString())).findFirst();
            if (userLoginOptional.isPresent()) {
                return userLoginOptional.get().getCredentials();
            }
        }
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        if (!CollectionUtils.isEmpty(userLogins)) {
            Optional<UserLogin> userLoginOptional = userLogins.stream().filter(it -> Objects.equals(it.getIdentity(), AuthType.password.getType().toString())).findFirst();
            if (userLoginOptional.isPresent()) {
                return userLoginOptional.get().getCredentialsNonExpired();
            }
        }
        return false;
    }

    @Override
    public boolean isEnabled() {
        return Objects.equals(Boolean.TRUE, this.isEnabled);
    }

    public void setEnabled(Boolean enabled) {
        isEnabled = Objects.equals(Boolean.TRUE, enabled);
    }

    public String getTelephone() {
        return telephone;
    }

    public void setTelephone(String telephone) {
        this.telephone = telephone;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    public List<UserLogin> getUserLogins() {
        return userLogins;
    }

    public void setUserLogins(List<UserLogin> userLogins) {
        this.userLogins = userLogins;
    }
}
