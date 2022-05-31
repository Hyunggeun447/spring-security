package com.prgrms.devcourse.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserServiceTest {

  @Autowired
  private UserService userService;

  @Test
  public void 사용자_추가_테스트() {
    User user1 = userService.join(
      mockOAuth2User("1", getAttributes("A", "image_url")),
      "kakao"
    );
    assertThat(user1).isNotNull();

    User user2 = userService.join(
      mockOAuth2User("2", getAttributes("B", null)),
      "kakao"
    );
    assertThat(user2).isNotNull();

    // 기존 사용자 정보를 추가해본다
    User user3 = userService.join(
      mockOAuth2User("1", getAttributes("A", "image_url")),
      "kakao"
    );
    assertThat(user3).isNotNull();
    assertThat(user3.getId()).isEqualTo(user1.getId());
    assertThat(user3.getUsername()).isEqualTo(user1.getUsername());
    assertThat(user3.getProvider()).isEqualTo(user1.getProvider());
    assertThat(user3.getProviderId()).isEqualTo(user1.getProviderId());
    assertThat(user3.getProfileImage()).isEqualTo(user1.getProfileImage());
  }

  private Map<String, Object> getAttributes(String nickname, String profileImage) {
    Map<String, String> properties = new HashMap<>();
    properties.put("nickname", nickname);
    properties.put("profileImage", profileImage);

    Map<String, Object> attributes = new HashMap<>();
    attributes.put("properties", properties);
    return attributes;
  }

  private OAuth2User mockOAuth2User(String name, Map<String, Object> attributes) {
    OAuth2User oauth2User = mock(OAuth2User.class);
    given(oauth2User.getName()).willReturn(name);
    given(oauth2User.getAttributes()).willReturn(attributes);
    return oauth2User;
  }

}