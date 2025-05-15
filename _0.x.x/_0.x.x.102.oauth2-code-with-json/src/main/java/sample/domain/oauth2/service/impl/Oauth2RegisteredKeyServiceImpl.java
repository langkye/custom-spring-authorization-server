package sample.domain.oauth2.service.impl;

import com.devskiller.friendly_id.FriendlyId;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import sample.domain.oauth2.model.Oauth2RegisteredKey;
import sample.domain.oauth2.repository.IOauth2RegisteredKeyRepository;
import sample.domain.oauth2.service.IOauth2RegisteredKeyService;

import javax.annotation.Resource;
import javax.crypto.SecretKey;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaUpdate;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.beans.PropertyDescriptor;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Service
public class Oauth2RegisteredKeyServiceImpl implements IOauth2RegisteredKeyService {
    @Resource
    private IOauth2RegisteredKeyRepository oauth2RegisteredKeyRepository;
    @PersistenceContext
    private EntityManager em;

    @Override
    public Page<Oauth2RegisteredKey> queryPage(Oauth2RegisteredKey oauth2RegisteredKey) {
        Pageable pageable = Pageable.ofSize(10);
        Example<Oauth2RegisteredKey> example = Example.of(oauth2RegisteredKey);
        return oauth2RegisteredKeyRepository.findAll(example, pageable);
    }

    @Override
    public Oauth2RegisteredKey queryOneByKeyId(String keyId) {
        return oauth2RegisteredKeyRepository.findByKeyId(keyId).orElse(null);
    }

    @Override
    public List<Oauth2RegisteredKey> queryAllActiveKeys() {
        Oauth2RegisteredKey oauth2RegisteredKey = new Oauth2RegisteredKey();
        oauth2RegisteredKey.setStatus(1L);

        ExampleMatcher matching = ExampleMatcher.matching();
        matching.withMatcher("keyId", ExampleMatcher.GenericPropertyMatchers.startsWith()); // keyId like 'keyId%'
        Example<Oauth2RegisteredKey> example = Example.of(oauth2RegisteredKey, matching);

        Specification<Oauth2RegisteredKey> specification = (root, query, builder) -> {
            List<Predicate> list4and = new ArrayList<>();
            
            //精确查询
            list4and.add(builder.equal(root.get("status"), oauth2RegisteredKey.getStatus()));
            
            //模糊查询
            //list4and.add(builder.like(root.get("algorithm"), "%" + oauth2RegisteredKey.getAlgorithm() + "%"));
            
            //范围查询
            list4and.add(builder.lessThan(root.get("keyIssuedAt"), new Date()));

            Predicate[] predicates4and = new Predicate[list4and.size()];
            list4and.toArray(predicates4and);
            Predicate and = builder.and(predicates4and);
            //return and;


            List<Predicate> list4or = new ArrayList<>();
            list4or.add(builder.greaterThan(root.get("keyExpiresAt"), new Date()));
            list4or.add(builder.isNull(root.get("keyExpiresAt")));

            Predicate[] predicates4or = new Predicate[list4or.size()];
            list4or.toArray(predicates4or);
            Predicate or = builder.or(predicates4or);
            
            return query.where(and, or).getRestriction();
        };
        
        return oauth2RegisteredKeyRepository.findAll(specification);
    }

    /**
     * 生成密钥对。
     * 同一种算法的密钥最多允许一条激活且未过期的记录（激活 && 未过期 && 未删除）：
     *      - 默认生成密钥未激活
     *      - 默认生成密钥永久有效
     *      - 默认生成密钥永久有效
     * 同一种算法的密钥最多允许一条激活且未过期的记录（激活 && 未过期 && 未删除）。
     * 
     * @param oauth2RegisteredKey request
     * @return response
     */
    @Override
    public Oauth2RegisteredKey generate(Oauth2RegisteredKey oauth2RegisteredKey) {
        String algorithm = oauth2RegisteredKey.getAlgorithm();
        Assert.notNull(algorithm, "algorithm can not be null");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forName(algorithm);
        boolean isHmac = signatureAlgorithm.isHmac();
        boolean isRsa = signatureAlgorithm.isRsa();
        boolean isEllipticCurve = signatureAlgorithm.isEllipticCurve();
        
        // md5
        // rsa
        // sm1
        // sm2
        // sm3
        // sm4
        // hs512
        // ...

        String privateKeyHexString = null;
        String publicKeyHexString = null;
        if (isHmac) {
            SecretKey key = Keys.secretKeyFor(signatureAlgorithm);
            privateKeyHexString = Base64.getEncoder().encodeToString(key.getEncoded());
        }
        if (isRsa) {
            //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            //keyPairGenerator.initialize(2048);
            //keyPair = keyPairGenerator.generateKeyPair();
            
            KeyPair keyPair = Keys.keyPairFor(signatureAlgorithm);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            privateKeyHexString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            publicKeyHexString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        }
        if (isEllipticCurve) {
            KeyPair keyPair = Keys.keyPairFor(signatureAlgorithm);
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

            privateKeyHexString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            publicKeyHexString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        }

        
        Oauth2RegisteredKey entity = new Oauth2RegisteredKey();
        entity.setIsDelete(0L);
        entity.setStatus(0L);
        entity.setKeyId(FriendlyId.createFriendlyId());
        entity.setKeyIssuedAt(new Date());
        entity.setAlgorithm(algorithm);
        entity.setPrivateKey(privateKeyHexString);
        entity.setPublicKey(publicKeyHexString);
        
        oauth2RegisteredKeyRepository.save(entity);
        return entity;
    }

    @Transactional
    @Override
    public Oauth2RegisteredKey active(Oauth2RegisteredKey oauth2RegisteredKey) {
        Assert.notNull(oauth2RegisteredKey.getId(), "id can not be null");

        Oauth2RegisteredKey entity = new Oauth2RegisteredKey();
        entity.setId(oauth2RegisteredKey.getId());
        entity.setStatus(1L);

        //oauth2RegisteredKeyRepository.save(entity);
        //return oauth2RegisteredKey;
        
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaUpdate<Oauth2RegisteredKey> update = cb.createCriteriaUpdate(Oauth2RegisteredKey.class);
        Root<Oauth2RegisteredKey> root = update.from(Oauth2RegisteredKey.class);
        // WHERE id = :id
        update.where(cb.equal(root.get("id"), oauth2RegisteredKey.getId()));

        update.set(root.get("status"), 1L);

        // 动态判断并设置要更新的字段
        //if (oauth2RegisteredKey.getKeyExpiresAt() != null) {
        //    update.set(root.get("keyExpiresAt"), oauth2RegisteredKey.getKeyExpiresAt());
        //}
        // ...其他字段同理

        // 执行 UPDATE
        em.createQuery(update).executeUpdate();
        
        return entity;
    }

    @Transactional
    @Override
    public Oauth2RegisteredKey invalid(Oauth2RegisteredKey oauth2RegisteredKey) {
        Assert.notNull(oauth2RegisteredKey.getId(), "id can not be null");

        Oauth2RegisteredKey entity = new Oauth2RegisteredKey();
        entity.setId(oauth2RegisteredKey.getId());
        entity.setStatus(0L);

        //oauth2RegisteredKeyRepository.save(entity);
        //return oauth2RegisteredKey;

        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaUpdate<Oauth2RegisteredKey> update = cb.createCriteriaUpdate(Oauth2RegisteredKey.class);
        Root<Oauth2RegisteredKey> root = update.from(Oauth2RegisteredKey.class);
        // WHERE id = :id
        update.where(cb.equal(root.get("id"), oauth2RegisteredKey.getId()));

        update.set(root.get("status"), 0L);

        // 动态判断并设置要更新的字段
        //if (oauth2RegisteredKey.getKeyExpiresAt() != null) {
        //    update.set(root.get("keyExpiresAt"), oauth2RegisteredKey.getKeyExpiresAt());
        //}
        // ...其他字段同理

        // 执行 UPDATE
        em.createQuery(update).executeUpdate();

        return entity;
    }

    @Transactional
    @Override
    public Oauth2RegisteredKey updateExpiresAt(Oauth2RegisteredKey oauth2RegisteredKey) {
        Assert.notNull(oauth2RegisteredKey.getId(), "id can not be null");
        Assert.notNull(oauth2RegisteredKey.getKeyExpiresAt(), "keyExpiresAt can not be null");

        Oauth2RegisteredKey entity = new Oauth2RegisteredKey();
        entity.setId(oauth2RegisteredKey.getId());
        entity.setKeyExpiresAt(oauth2RegisteredKey.getKeyExpiresAt());

        //oauth2RegisteredKeyRepository.save(entity);
        //return oauth2RegisteredKey;

        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaUpdate<Oauth2RegisteredKey> update = cb.createCriteriaUpdate(Oauth2RegisteredKey.class);
        Root<Oauth2RegisteredKey> root = update.from(Oauth2RegisteredKey.class);
        // WHERE id = :id
        update.where(cb.equal(root.get("id"), oauth2RegisteredKey.getId()));

        update.set(root.get("keyExpiresAt"), Optional.ofNullable(oauth2RegisteredKey.getKeyExpiresAt()).orElse(new Date()));

        // 动态判断并设置要更新的字段
        //if (oauth2RegisteredKey.getKeyExpiresAt() != null) {
        //    update.set(root.get("keyExpiresAt"), oauth2RegisteredKey.getKeyExpiresAt());
        //}
        // ...其他字段同理

        // 执行 UPDATE
        em.createQuery(update).executeUpdate();

        return entity;
    }

    @Transactional
    @Override
    public Oauth2RegisteredKey dynamicUpdate(Oauth2RegisteredKey oauth2RegisteredKey) {
        Assert.notNull(oauth2RegisteredKey.getId(), "id can not be null");

        Oauth2RegisteredKey target = em.find(Oauth2RegisteredKey.class, oauth2RegisteredKey.getId());
        BeanUtils.copyProperties(oauth2RegisteredKey, target, getNullPropertyNames(oauth2RegisteredKey));

        oauth2RegisteredKeyRepository.save(target);
        
        return target;
    }

    public static String[] getNullPropertyNames(Object source) {
        final BeanWrapper src = new BeanWrapperImpl(source);
        return Arrays.stream(src.getPropertyDescriptors())
                .map(PropertyDescriptor::getName)
                .filter(name -> src.getPropertyValue(name) == null)
                .toArray(String[]::new);
    }
}
