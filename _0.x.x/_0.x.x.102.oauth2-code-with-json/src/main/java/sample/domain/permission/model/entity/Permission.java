package sample.domain.permission.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.sun.istack.NotNull;
import org.springframework.security.core.GrantedAuthority;
import sample.domain.role.model.entity.Role;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.Set;

@Entity
@Table(name = "system_permission")
public class Permission implements GrantedAuthority, Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "create_by_user_id")
    private Long createByUserId;

    @Column(name = "create_by_user_name")
    private String createByUserName;

    @Column(name = "create_time")
    @JsonIgnore
    private Date createTime;

    @Column(name = "update_by_user_id")
    private Long updateByUserId;

    @Column(name = "update_by_user_name")
    private String updateByUserName;

    @Column(name = "update_time")
    private Date updateTime;

    @Column(name = "status")
    private Long status;

    @Column(name = "is_delete")
    private Long isDelete;

    @NotNull
    @Column(name = "authority")
    private String authority;

    @NotNull
    @Column(name = "display_name")
    private String displayName;

    @JsonIgnore
    @ManyToMany(mappedBy = "permissions")
    private Set<Role> roles;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getCreateByUserId() {
        return createByUserId;
    }

    public void setCreateByUserId(Long createByUserId) {
        this.createByUserId = createByUserId;
    }

    public String getCreateByUserName() {
        return createByUserName;
    }

    public void setCreateByUserName(String createByUserName) {
        this.createByUserName = createByUserName;
    }

    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public Long getUpdateByUserId() {
        return updateByUserId;
    }

    public void setUpdateByUserId(Long updateByUserId) {
        this.updateByUserId = updateByUserId;
    }

    public String getUpdateByUserName() {
        return updateByUserName;
    }

    public void setUpdateByUserName(String updateByUserName) {
        this.updateByUserName = updateByUserName;
    }

    public Date getUpdateTime() {
        return updateTime;
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

    public Long getStatus() {
        return status;
    }

    public void setStatus(Long status) {
        this.status = status;
    }

    public Long getIsDelete() {
        return isDelete;
    }

    public void setIsDelete(Long isDelete) {
        this.isDelete = isDelete;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
