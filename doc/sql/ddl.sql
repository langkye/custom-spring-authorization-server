/* ===============================================================================================================
   ================================================ authorize ddl ================================================
   ===============================================================================================================
-- spring-security-oauth2-authorization-server-x.x.x.jar
org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql
org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql
org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql

-- spring-security-oauth2-client-x.x.x.jar
org/springframework/security/oauth2/client/oauth2-client-schema.sql -- of mysql
org/springframework/security/oauth2/client/oauth2-client-schema-postgres.sql -- of postgres
*/

create table oauth2_authorization
(
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    blob          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      blob          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   blob          DEFAULT NULL,
    access_token_value            blob          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         blob          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           blob          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        blob          DEFAULT NULL,
    refresh_token_value           blob          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        blob          DEFAULT NULL,
    PRIMARY KEY (id)
);

create table oauth2_authorization_consent
(
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

create table oauth2_registered_client
(
    id                            varchar(100)                        not null
        primary key,
    client_id                     varchar(100)                        not null,
    client_id_issued_at           timestamp default CURRENT_TIMESTAMP not null,
    client_secret                 varchar(200)                        null,
    client_secret_expires_at      timestamp                           null,
    client_name                   varchar(200)                        not null,
    client_authentication_methods varchar(1000)                       not null,
    authorization_grant_types     varchar(1000)                       not null,
    redirect_uris                 varchar(1000)                       null,
    scopes                        varchar(1000)                       not null,
    client_settings               varchar(2000)                       not null,
    token_settings                varchar(2000)                       not null
);





/* ===============================================================================================================
   ================================================ customize ddl ================================================
   ===============================================================================================================
*/
create table system_user
(
    id                  bigint auto_increment comment '数据标识'
        primary key,
    create_by_user_id   int          null comment '创建用户id',
    create_by_user_name varchar(128) null comment '创建用户姓名',
    create_time         datetime     null comment '创建时间',
    update_by_user_id   int          null comment '修改用户id',
    update_by_user_name varchar(128) null comment '修改用户姓名',
    update_time         datetime     null comment '修改时间',
    status              int          null comment '数据状态',
    is_delete           int          null comment '是否删除',
    system_organize_id  int          null comment '外键：单位ID',
    username            varchar(64)  null comment '用户名',
    user_type           int          null comment '用户类型',
    login_types         varchar(128) null comment '登录方式(数组)',
    ips                 varchar(255) null comment '允许登录的IP，默认为所有，支持通配符',
    name                varchar(128) null comment '姓名',
    gender              int          null comment '性别',
    telephone           varchar(255) null comment '手机号',
    email               varchar(255) null comment '邮箱',
    zip                 varchar(255) null comment '邮编',
    birthday            date         null comment '出生日期',
    nationality         int          null comment '国籍',
    census_register     int          null comment '户籍',
    address             varchar(255) null comment '通信地址',
    certificate_type    int          null comment '证件类型',
    certificate_no      varchar(64)  null comment '证件号码',
    account_non_expired bigint       null comment '账户未过期',
    account_non_locked  bigint       null comment '账号未锁定',
    is_enabled          bigint       null comment '是否启用',
    constraint username
        unique (username)
)
comment '用户信息';

create index login_types
    on system_user (login_types);


create table system_user_login
(
    id                      bigint auto_increment comment '数据标识'
        primary key,
    create_by_user_id       int          null comment '创建用户id',
    create_by_user_name     varchar(128) null comment '创建用户姓名',
    create_time             datetime     null comment '创建时间',
    update_by_user_id       int          null comment '修改用户id',
    update_by_user_name     varchar(128) null comment '修改用户姓名',
    update_time             datetime     null comment '修改时间',
    status                  int          null comment '数据状态',
    is_delete               int          null comment '是否删除',
    system_user_id          bigint       null comment '外键用户ID',
    identity                varchar(64)  null comment '登录标识',
    credentials             varchar(256) null comment '登录凭证',
    mfa_type                int          null comment 'MFA类型',
    enable_mfa              int          null comment '是否启用MFA认证',
    last_login_time         datetime     null comment '最近登录时间',
    last_logout_time        datetime     null comment '最近登出时间',
    credentials_non_expired bigint       null comment '凭证未过期',
    constraint system_user_login_system_user_id_fk
        foreign key (system_user_id) references system_user (id)
)
    comment '用户登录信息';

create table system_role
(
    id                       bigint auto_increment comment '数据标识'
        primary key,
    create_by_user_id        int          null comment '创建用户id',
    create_by_user_name      varchar(128) null comment '创建用户姓名',
    create_time              datetime     null comment '创建时间',
    update_by_user_id        int          null comment '修改用户id',
    update_by_user_name      varchar(128) null comment '修改用户姓名',
    update_time              datetime     null comment '修改时间',
    status                   int          null comment '数据状态',
    is_delete                int          null comment '是否删除',
    system_subsystem_id      int          null comment '所属子系统',
    name                     varchar(64)  null comment '角色名称',
    code                     varchar(64)  null comment '角色编码',
    module_name              varchar(64)  null comment '模块名称',
    authority_identification varchar(128) null comment '权限标识',
    is_system                int          null comment '是否系统角色',
    is_default               int          null comment '是否默认角色',
    order_no                 int          null comment '角色排序'
)
    comment '系统角色';



create table system_user_role
(
    user_id bigint not null,
    role_id bigint not null,
    primary key (user_id, role_id),
    constraint fk_users_roles_role_id_mooc_roles_id
        foreign key (role_id) references system_role (id),
    constraint fk_users_roles_user_id_mooc_users_id
        foreign key (user_id) references system_user (id)
);


/* ===============================================================================================================
   ================================================ data.     dml ================================================
   ===============================================================================================================
*/
INSERT INTO authorization_server.oauth2_registered_client (id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name, client_authentication_methods, authorization_grant_types, redirect_uris, scopes, client_settings, token_settings) VALUES ('ea8af5a4-4fd0-4151-99af-feae04e3d0fb', 'messaging-client', '2023-10-30 09:35:46', '{noop}secret', null, 'ea8af5a4-4fd0-4151-99af-feae04e3d0fb', 'client_secret_post', 'refresh_token,client_credentials,authorization_code', 'http://127.0.0.1:8080/authorized,http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc', 'openid,profile,message.read,message.write', '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":true}', '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}');
INSERT INTO authorization_server.oauth2_registered_client (id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name, client_authentication_methods, authorization_grant_types, redirect_uris, scopes, client_settings, token_settings) VALUES ('ea8af5a4-4fd0-4151-99af-feae04e3d0fc', '19999999999', '2023-10-30 09:35:46', '{noop}secret', null, 'ea8af5a4-4fd0-4151-99af-feae04e3d0fc', 'client_secret_post', 'refresh_token,client_credentials,authorization_code', 'http://127.0.0.1:8080/authorized,http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc', 'openid,profile,message.read,message.write', '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}', '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}');
INSERT INTO authorization_server.oauth2_registered_client (id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name, client_authentication_methods, authorization_grant_types, redirect_uris, scopes, client_settings, token_settings) VALUES ('ea8af5a4-4fd0-4151-99af-feae04e3d0fd', '18888888888', '2023-10-30 09:35:46', '{noop}secret', null, 'ea8af5a4-4fd0-4151-99af-feae04e3d0fd', 'client_secret_post', 'refresh_token,client_credentials,authorization_code', 'http://127.0.0.1:8080/authorized,http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc', 'openid,profile,message.read,message.write', '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":true}', '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}');

INSERT INTO authorization_server.oauth2_authorization_consent (registered_client_id, principal_name, authorities) VALUES ('ea8af5a4-4fd0-4151-99af-feae04e3d0fb', 'user', 'SCOPE_openid,SCOPE_message.read,SCOPE_message.write,SCOPE_profile');
INSERT INTO authorization_server.oauth2_authorization_consent (registered_client_id, principal_name, authorities) VALUES ('ea8af5a4-4fd0-4151-99af-feae04e3d0fc', '19999999999', 'SCOPE_openid,SCOPE_message.read,SCOPE_message.write,SCOPE_profile');
INSERT INTO authorization_server.oauth2_authorization_consent (registered_client_id, principal_name, authorities) VALUES ('ea8af5a4-4fd0-4151-99af-feae04e3d0fc', 'user', 'SCOPE_openid,SCOPE_message.read,SCOPE_message.write,SCOPE_profile');
INSERT INTO authorization_server.oauth2_authorization_consent (registered_client_id, principal_name, authorities) VALUES ('ea8af5a4-4fd0-4151-99af-feae04e3d0fd', '18888888888', 'SCOPE_openid,SCOPE_message.read,SCOPE_message.write,SCOPE_profile');

INSERT INTO authorization_server.system_user (id, create_by_user_id, create_by_user_name, create_time, update_by_user_id, update_by_user_name, update_time, status, is_delete, system_organize_id, username, user_type, login_types, ips, name, gender, telephone, email, zip, birthday, nationality, census_register, address, certificate_type, certificate_no, account_non_expired, account_non_locked, is_enabled) VALUES (0, 0, 'admin', '2023-11-01 15:01:18', 0, 'admin', '2023-11-01 15:01:32', 10, 0, null, 'admin', null, '[10]', null, null, null, '18888888888', null, null, null, null, null, null, null, null, 1, 1, 1);
INSERT INTO authorization_server.system_user (id, create_by_user_id, create_by_user_name, create_time, update_by_user_id, update_by_user_name, update_time, status, is_delete, system_organize_id, username, user_type, login_types, ips, name, gender, telephone, email, zip, birthday, nationality, census_register, address, certificate_type, certificate_no, account_non_expired, account_non_locked, is_enabled) VALUES (1, 1, 'user', '2023-11-01 15:01:18', 0, 'user', '2023-11-01 15:01:32', 10, 0, null, 'user', null, '[10]', null, null, null, '19999999999', null, null, null, null, null, null, null, null, 1, 1, 1);

INSERT INTO authorization_server.system_user_login (id, create_by_user_id, create_by_user_name, create_time, update_by_user_id, update_by_user_name, update_time, status, is_delete, system_user_id, identity, credentials, mfa_type, enable_mfa, last_login_time, last_logout_time, credentials_non_expired) VALUES (1, 0, 'admin', '2023-11-01 15:05:11', 0, 'admin', '2023-11-01 15:05:17', 10, 0, 0, '10', '{bcrypt}$2a$10$/XvjwHz01a/r6HGf6RNjkuqS1GtZGECd9HYPbVpN/xWjUHCewiXhu', null, null, null, null, 1);
