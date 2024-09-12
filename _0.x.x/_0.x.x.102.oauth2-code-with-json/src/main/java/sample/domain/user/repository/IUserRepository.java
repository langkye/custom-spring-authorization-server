package sample.domain.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;
import sample.domain.user.model.entity.User;

import java.util.Optional;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Repository
public interface IUserRepository extends JpaRepository<User, Long> {
    @NonNull Optional<User> findById(@NonNull Long id);
    Optional<User> findByUsername(String username);
    Optional<User> findByTelephone(String telephone);
}
