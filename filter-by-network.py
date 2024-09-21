import json

# 파일 경로 설정
file_path = "enterprise-attack.json"

# JSON 데이터 로드
with open(file_path, 'r') as f:
    attack_data = json.load(f)

# ATT&CK 기술 필터링
techniques = [obj for obj in attack_data['objects'] if obj['type'] == 'attack-pattern']

# 네트워크 관련 키워드
network_keywords = ["network", "traffic", "packet", "connection", "flow", "port", "protocol"]
network_techniques = []

# 네트워크 관련 기술 필터링
for technique in techniques:
    description = technique.get('description', '').lower()
    detection = technique.get('x_mitre_detection', '').lower()
    
    if any(keyword in description or keyword in detection for keyword in network_keywords):
        network_techniques.append(technique)

# 결과 출력
total_techniques = len(techniques)
network_techniques_count = len(network_techniques)

print(f"총 ATT&CK 기술 수: {total_techniques}")
print(f"네트워크 기반 탐지에 적합한 기술 수: {network_techniques_count}")
print(f"비율: {network_techniques_count / total_techniques * 100:.2f}%")

# 네트워크 관련 기술 중 일부 예시 출력
for tech in network_techniques[:5]:  # 처음 5개만 출력
    print(f"ID: {tech['external_references'][0]['external_id']}, Name: {tech['name']}")
