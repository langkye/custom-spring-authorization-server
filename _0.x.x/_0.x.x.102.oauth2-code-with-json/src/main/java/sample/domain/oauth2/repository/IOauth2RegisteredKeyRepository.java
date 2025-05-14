package sample.domain.oauth2.repository;

import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;
import sample.domain.oauth2.model.Oauth2RegisteredKey;

import java.util.Optional;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Repository
public interface IOauth2RegisteredKeyRepository 
        //extends JpaRepository<Oauth2RegisteredKey, Long> 
        extends CrudRepository<Oauth2RegisteredKey, Long> 
{
    @NonNull Optional<Oauth2RegisteredKey> findById(@NonNull Long id);
    Optional<Oauth2RegisteredKey> findByKeyId(String keyId);

    @NonNull Page<Oauth2RegisteredKey> findAll(@NonNull Pageable pageable);

    @NonNull <S extends Oauth2RegisteredKey> Page<S> findAll(@NonNull Example<S> example, @NonNull Pageable pageable);
}
