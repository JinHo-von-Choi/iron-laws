package demo;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface MemberMapper {
    Member selectMember(String userId);
    int resetLoginFailCount(String userId);
}
