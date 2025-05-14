package sample.domain.oauth2.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import org.hibernate.annotations.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import sample.config.provider.AuthType;
import sample.domain.login.model.entity.UserLogin;
import sample.domain.role.model.entity.Role;

import javax.persistence.*;
import javax.persistence.Entity;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@DynamicUpdate
@DynamicInsert
@SQLDelete(sql = "update oauth2_registered_key set is_delete = 1 where id = ?")
@Where(clause = "is_delete = 0")
@Entity
@Table(name = "oauth2_registered_key")
public class Oauth2RegisteredKey implements Serializable {
    private static final long serialVersionUID = 1L;
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "create_by_user_id")
    private Long createByUserId;
    @Column(name = "create_by_user_name")
    private String createByUserName;
    @Column(name = "create_time")
    @CreatedDate
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
    
    @Column(name = "key_issued_at")
    private Date keyIssuedAt;
    @Column(name = "key_expires_at")
    private Date keyExpiresAt;
    @Column(name = "key_id")
    private String keyId;
    @Column(name = "algorithm")
    private String algorithm;
    //@JsonIgnore
    @Column(name = "private_key")
    private String privateKey;
    @Column(name = "public_key")
    private String publicKey;

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

    public Date getKeyIssuedAt() {
        return keyIssuedAt;
    }

    public void setKeyIssuedAt(Date keyIssuedAt) {
        this.keyIssuedAt = keyIssuedAt;
    }

    public Date getKeyExpiresAt() {
        return keyExpiresAt;
    }

    public void setKeyExpiresAt(Date keyExpiresAt) {
        this.keyExpiresAt = keyExpiresAt;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
