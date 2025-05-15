package sample.web;

import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sample.domain.oauth2.model.Oauth2RegisteredKey;
import sample.domain.oauth2.service.IOauth2RegisteredKeyService;

import javax.annotation.Resource;

/**
 * @author langkye
 * @since 1.0.0.RELEASE
 */
@RestController
@RequestMapping("/api/key")
public class Oauth2RegisteredKeyController {
    @Resource
    private IOauth2RegisteredKeyService oauth2RegisteredKeyService;

    @RequestMapping("/queryPage")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object queryPage(@RequestBody Oauth2RegisteredKey entity) {
        return oauth2RegisteredKeyService.queryPage(entity);
    }

    @RequestMapping("/queryOneByKeyId")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object queryOneByKeyId(@RequestBody Oauth2RegisteredKey entity) {
        Assert.notNull(entity.getKeyId(), "keyId can not be null");
        return oauth2RegisteredKeyService.queryOneByKeyId(entity.getKeyId());
    }

    @RequestMapping("/queryAllActiveKeys")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object queryAllActiveKeys(@RequestBody Oauth2RegisteredKey entity) {
        return oauth2RegisteredKeyService.queryAllActiveKeys();
    }

    @RequestMapping("/generate")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object generate(@RequestBody Oauth2RegisteredKey entity) {
        return oauth2RegisteredKeyService.generate(entity);
    }

    @RequestMapping("/active")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object active(@RequestBody Oauth2RegisteredKey entity) {
        return oauth2RegisteredKeyService.active(entity);
    }
    
    @RequestMapping("/invalid")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object invalid(@RequestBody Oauth2RegisteredKey entity) {
        return oauth2RegisteredKeyService.invalid(entity);
    }

    @RequestMapping("/updateExpiresAt")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object updateExpiresAt(@RequestBody Oauth2RegisteredKey entity) {
        return oauth2RegisteredKeyService.updateExpiresAt(entity);
    }

    @RequestMapping("/dynamicUpdate")
    //@PreAuthorize("hasAnyAuthority('USER', 'user') or hasAnyRole('USER', 'user')")
    public Object dynamicUpdate(@RequestBody Oauth2RegisteredKey entity) {
        return oauth2RegisteredKeyService.dynamicUpdate(entity);
    }
}
