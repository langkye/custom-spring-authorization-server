package sample.domain.user.model.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;
import org.mapstruct.factory.Mappers;
import sample.domain.user.model.entity.User;
import sample.domain.user.model.response.UserVo;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface UserMapper {
    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);

    UserVo toVo(User entity);    
}
