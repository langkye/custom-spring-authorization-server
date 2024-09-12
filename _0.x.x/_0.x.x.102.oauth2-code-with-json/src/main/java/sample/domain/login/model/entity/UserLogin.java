package sample.domain.login.model.entity;

import com.alibaba.fastjson2.annotation.JSONField;
import com.fasterxml.jackson.annotation.*;
import org.springframework.data.domain.AbstractAggregateRoot;
import sample.domain.user.model.entity.User;

import javax.persistence.*;
import java.io.Serializable;
import java.util.*;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@JsonTypeInfo(
        //use = JsonTypeInfo.Id.NAME,
        use = JsonTypeInfo.Id.CLASS,
        include = JsonTypeInfo.As.PROPERTY,
        //property = "type"
        property = "@class"
)
@JsonSubTypes({
        @JsonSubTypes.Type(value = UserLogin.class, name = "userLogin")
})
@Entity
@Table(name = "system_user_login")
public class UserLogin extends AbstractAggregateRoot<UserLogin> implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "create_by_user_id")
    private Long createByUserId;

    @Column(name = "create_by_user_name")
    private String createByUserName;

    @Column(name = "create_time")
    //@Temporal(TemporalType.DATE)
    //@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    @JsonIgnore
    private Date createTime;

    @Column(name = "update_by_user_id")
    private Long updateByUserId;

    @Column(name = "update_by_user_name")
    private String updateByUserName;

    @Column(name = "update_time")
    //@JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    @JsonIgnore
    private Date updateTime;

    @Column(name = "status")
    private Long status;

    @Column(name = "is_delete")
    private Long isDelete;

    //@Column(name = "system_user_id")
    //private Long systemUserId;

    @Column(name = "identity")
    private String identity;

    @Column(name = "credentials")
    @JsonIgnore
    private String credentials;

    @Column(name = "mfa_type")
    @JsonIgnore
    private Long mfaType;

    @Column(name = "enable_mfa")
    @JsonIgnore
    private Long enableMfa;

    @Column(name = "last_login_time")
    @JsonIgnore
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date lastLoginTime;

    @Column(name = "last_logout_time")
    @JsonIgnore
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date lastLogoutTime;

    @Column(name = "credentials_non_expired")
    @JsonIgnore
    private Boolean credentialsNonExpired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "system_user_id")
    @JsonBackReference
    @JSONField(serialize = false)
    private User user;

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


    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    public Long getMfaType() {
        return mfaType;
    }

    public void setMfaType(Long mfaType) {
        this.mfaType = mfaType;
    }

    public Long getEnableMfa() {
        return enableMfa;
    }

    public void setEnableMfa(Long enableMfa) {
        this.enableMfa = enableMfa;
    }

    public Date getLastLoginTime() {
        return lastLoginTime;
    }

    public void setLastLoginTime(Date lastLoginTime) {
        this.lastLoginTime = lastLoginTime;
    }

    public Date getLastLogoutTime() {
        return lastLogoutTime;
    }

    public void setLastLogoutTime(Date lastLogoutTime) {
        this.lastLogoutTime = lastLogoutTime;
    }

    public Boolean getCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public void setCredentialsNonExpired(Boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
    
    
}
