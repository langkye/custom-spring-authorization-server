package sample.domain.role.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.*;
import sample.domain.permission.model.entity.Permission;
import sample.domain.user.model.entity.User;

import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * 角色实体类，实现 GrantedAuthority 接口
 */
@Entity
@Table(name = "system_role")
public class Role implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * 自增长 ID，唯一标识
     */
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

    @Column(name = "system_subsystem_id")
    private Long systemSubsystemId;

    @Column(name = "name")
    private String name;

    @Column(name = "code")
    private String code;

    @Column(name = "module_name")
    private String moduleName;

    @Column(name = "authority_identification")
    private String authorityIdentification;

    @Column(name = "is_system")
    private Long isSystem;

    @Column(name = "is_default")
    private Long isDefault;

    @Column(name = "order_no")
    private Long orderNo;

    @JsonIgnore
    @Fetch(FetchMode.JOIN)
    @ManyToMany
    @JoinTable(
        name = "system_role_permission",
        joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"),
        inverseJoinColumns = @JoinColumn(name = "permission_id", referencedColumnName = "id"))
    @Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
    @BatchSize(size = 20)
    private Set<Permission> permissions = new HashSet<>();

    @JsonIgnore
    @ManyToMany(mappedBy = "roles")
    private Set<User> users;

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

    public Long getSystemSubsystemId() {
        return systemSubsystemId;
    }

    public void setSystemSubsystemId(Long systemSubsystemId) {
        this.systemSubsystemId = systemSubsystemId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getModuleName() {
        return moduleName;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getAuthorityIdentification() {
        return authorityIdentification;
    }

    public void setAuthorityIdentification(String authorityIdentification) {
        this.authorityIdentification = authorityIdentification;
    }

    public Long getIsSystem() {
        return isSystem;
    }

    public void setIsSystem(Long isSystem) {
        this.isSystem = isSystem;
    }

    public Long getIsDefault() {
        return isDefault;
    }

    public void setIsDefault(Long isDefault) {
        this.isDefault = isDefault;
    }

    public Long getOrderNo() {
        return orderNo;
    }

    public void setOrderNo(Long orderNo) {
        this.orderNo = orderNo;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }
}
