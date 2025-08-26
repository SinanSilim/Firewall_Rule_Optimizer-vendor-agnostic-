# Firewall_Rule_Optimizer-vendor-agnostic-

Nasıl kullanılır (özet):

Örnek komut:

python firewall_rule_optimizer.py \
  --in rules_fgt.csv:fortigate \
  --in rules_pan.csv:panos \
  --out-dir out --report html,md,csv,json \
  --broad-prefix4 8 --broad-prefix6 32 --min-shadow-depth 1


Generic CSV için gerekli kolonlar: id,name,src,dst,service,action,disabled,log,hits,position

Object map (opsiyonel) ile isimli network/service gruplarını çözebilirsiniz:

python firewall_rule_optimizer.py --in rules_cp.csv:checkpoint --objects objects.yaml --out-dir out


Üretilen çıktılar: report.html, report.md, findings.csv, rules_normalized.json.

Tespitler:

Duplicate/aynı kurallar

Shadowed/etkisiz kalan kurallar

Any-Any-Any allow (kritik)

Aşırı geniş CIDR’lar (/0, /8 vs; ayarlanabilir)

0 hit/unused, disabled envanteri, log açılmamış allow kuralları

Birleştirme fırsatları (aynı src/dst/action için servisleri daraltma/kolaps).
