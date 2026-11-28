package demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MerchantPageController {
    private final PayoutMapper payoutMapper;

    public MerchantPageController(PayoutMapper p) { this.payoutMapper = p; }

    // 8. 연동 인증키 원문을 화면에 노출
    @GetMapping("/merchant/detail")
    public String merchantDetail(@RequestParam String mid, Model model) {
        Merchant m = payoutMapper.selectMerchant(mid);
        model.addAttribute("apiKey", m.getApiKey());
        return "merchant/detail";
    }
}
