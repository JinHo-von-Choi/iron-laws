package demo;

import java.util.List;
import java.util.Map;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface PayoutMapper {
    List<Map<String, Object>> selectPayoutList(@Param("mid") String mid, @Param("size") int size);
    Merchant selectMerchant(@Param("mid") String mid);
}
