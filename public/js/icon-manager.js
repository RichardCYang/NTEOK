
import { toggleModal, addIcon } from './ui-utils.js';
import * as api from './api-utils.js';

const THEME_ICONS = [
    { value: 'fa-solid fa-house', label: 'house home building 실내 집 홈' },
    { value: 'fa-solid fa-user', label: 'user person account profile 사용자 사람 계정 프로필' },
    { value: 'fa-solid fa-check', label: 'check done complete tick 확인 완료' },
    { value: 'fa-solid fa-download', label: 'download save fetch 다운로드 저장' },
    { value: 'fa-solid fa-magnifying-glass', label: 'magnifying-glass search find 검색 찾기' },
    { value: 'fa-solid fa-image', label: 'image picture photo 이미지 사진' },
    { value: 'fa-solid fa-phone', label: 'phone call telephone 전화' },
    { value: 'fa-solid fa-bars', label: 'bars menu list hamburger 메뉴 목록' },
    { value: 'fa-solid fa-envelope', label: 'envelope mail message email 메일 편지' },
    { value: 'fa-solid fa-star', label: 'star favorite like best 별 즐겨찾기' },
    { value: 'fa-solid fa-location-dot', label: 'location-dot map pin marker 위치 지도' },
    { value: 'fa-solid fa-music', label: 'music audio sound song 음악 소리' },
    { value: 'fa-solid fa-heart', label: 'heart love like 심장 하트' },
    { value: 'fa-solid fa-arrow-right', label: 'arrow-right next forward 화살표 다음' },
    { value: 'fa-solid fa-circle-xmark', label: 'circle-xmark close cancel remove 닫기 취소' },
    { value: 'fa-solid fa-cloud', label: 'cloud weather storage 구름 날씨' },
    { value: 'fa-solid fa-comment', label: 'comment chat message bubble 댓글 채팅' },
    { value: 'fa-solid fa-caret-down', label: 'caret-down arrow expand 아래 화살표' },
    { value: 'fa-solid fa-truck', label: 'truck delivery shipping 트럭 배달' },
    { value: 'fa-solid fa-pen', label: 'pen edit write 펜 쓰기 수정' },
    { value: 'fa-solid fa-file', label: 'file document paper 파일 문서' },
    { value: 'fa-solid fa-file-lines', label: 'file-lines document paper 파일 문서' },
    { value: 'fa-solid fa-gear', label: 'gear settings tool 설정 도구' },
    { value: 'fa-solid fa-trash-can', label: 'trash-can delete remove 쓰레기통 삭제' },
    { value: 'fa-solid fa-circle-left', label: 'circle-left back previous 뒤로' },
    { value: 'fa-solid fa-circle-right', label: 'circle-right forward next 앞으로' },
    { value: 'fa-solid fa-circle-up', label: 'circle-up up 위로' },
    { value: 'fa-solid fa-circle-down', label: 'circle-down down 아래로' },
    { value: 'fa-solid fa-calendar', label: 'calendar date event schedule 달력 일정' },
    { value: 'fa-solid fa-clock', label: 'clock time watch 시계 시간' },
    { value: 'fa-solid fa-bell', label: 'bell notification alert 종 알림' },
    { value: 'fa-solid fa-cart-shopping', label: 'cart-shopping buy shop e-commerce 쇼핑' },
    { value: 'fa-solid fa-clipboard', label: 'clipboard copy paste notes 클립보드' },
    { value: 'fa-solid fa-filter', label: 'filter sort organize 필터' },
    { value: 'fa-solid fa-circle-info', label: 'circle-info help about 정보 안내' },
    { value: 'fa-solid fa-circle-question', label: 'circle-question help ask 질문 도움말' },
    { value: 'fa-solid fa-circle-exclamation', label: 'circle-exclamation warning alert 경고' },
    { value: 'fa-solid fa-lock', label: 'lock secure private password 잠금 비밀번호' },
    { value: 'fa-solid fa-unlock', label: 'unlock open public 잠금해제' },
    { value: 'fa-solid fa-camera', label: 'camera photo capture 카메라 사진' },
    { value: 'fa-solid fa-video', label: 'video movie record 비디오 영상' },
    { value: 'fa-solid fa-eye', label: 'eye view see 보기 눈' },
    { value: 'fa-solid fa-eye-slash', label: 'eye-slash hide invisible 숨기기' },
    { value: 'fa-solid fa-print', label: 'print paper copy 인쇄 프린트' },
    { value: 'fa-solid fa-link', label: 'link url attachment 링크 연결' },
    { value: 'fa-solid fa-paperclip', label: 'paperclip attach file 클립 첨부' },
    { value: 'fa-solid fa-code', label: 'code programming dev 코드 개발' },
    { value: 'fa-solid fa-terminal', label: 'terminal console command 터미널' },
    { value: 'fa-solid fa-database', label: 'database storage server 데이터베이스' },
    { value: 'fa-solid fa-server', label: 'server host cloud 서버' },
    { value: 'fa-solid fa-mobile-screen', label: 'mobile-screen phone smartphone 모바일 핸드폰' },
    { value: 'fa-solid fa-laptop', label: 'laptop computer notebook 노트북' },
    { value: 'fa-solid fa-desktop', label: 'desktop monitor computer 데스크탑 모니터' },
    { value: 'fa-solid fa-microchip', label: 'microchip cpu hardware 칩 하드웨어' },
    { value: 'fa-solid fa-keyboard', label: 'keyboard input typing 키보드' },
    { value: 'fa-solid fa-mouse', label: 'mouse pointer click 마우스' },
    { value: 'fa-solid fa-battery-full', label: 'battery-full power energy 배터리 전원' },
    { value: 'fa-solid fa-wifi', label: 'wifi internet connection 와이파이' },
    { value: 'fa-solid fa-bluetooth', label: 'bluetooth wireless 블루투스 무선' },
    { value: 'fa-solid fa-headphones', label: 'headphones audio music 헤드폰 음악' },
    { value: 'fa-solid fa-microphone', label: 'microphone voice record 마이크 녹음' },
    { value: 'fa-solid fa-volleyball', label: 'volleyball sports game 배구 운동' },
    { value: 'fa-solid fa-basketball', label: 'basketball sports game 농구 운동' },
    { value: 'fa-solid fa-football', label: 'football sports game 축구 운동' },
    { value: 'fa-solid fa-baseball', label: 'baseball sports game 야구 운동' },
    { value: 'fa-solid fa-trophy', label: 'trophy win prize award 트로피 우승' },
    { value: 'fa-solid fa-medal', label: 'medal rank award 메달 상' },
    { value: 'fa-solid fa-gift', label: 'gift present surprise 선물' },
    { value: 'fa-solid fa-cake-candles', label: 'cake-candles birthday party 케이크 생일' },
    { value: 'fa-solid fa-utensils', label: 'utensils food restaurant 식사 음식점' },
    { value: 'fa-solid fa-mug-hot', label: 'mug-hot coffee tea drink 커피 차' },
    { value: 'fa-solid fa-wine-glass', label: 'wine-glass alcohol drink 와인 술' },
    { value: 'fa-solid fa-beer-mug-empty', label: 'beer-mug-empty alcohol drink 맥주 술' },
    { value: 'fa-solid fa-martini-glass', label: 'martini-glass cocktail drink 마티니 술' },
    { value: 'fa-solid fa-car', label: 'car vehicle drive 자동차' },
    { value: 'fa-solid fa-plane', label: 'plane flight travel 비행기 여행' },
    { value: 'fa-solid fa-train', label: 'train travel subway 기차 지하철' },
    { value: 'fa-solid fa-bus', label: 'bus travel transport 버스 교통' },
    { value: 'fa-solid fa-bicycle', label: 'bicycle cycle sport 자전거 운동' },
    { value: 'fa-solid fa-motorcycle', label: 'motorcycle bike transport 오토바이' },
    { value: 'fa-solid fa-ship', label: 'ship boat travel 배 여행' },
    { value: 'fa-solid fa-rocket', label: 'rocket space launch 로켓 우주' },
    { value: 'fa-solid fa-briefcase', label: 'briefcase work business job 서류가방 업무' },
    { value: 'fa-solid fa-wallet', label: 'wallet money cash 지갑 돈' },
    { value: 'fa-solid fa-credit-card', label: 'credit-card payment money 신용카드 결제' },
    { value: 'fa-solid fa-money-bill', label: 'money-bill cash payment 돈 현금' },
    { value: 'fa-solid fa-chart-line', label: 'chart-line growth data 차트 성장' },
    { value: 'fa-solid fa-chart-pie', label: 'chart-pie data statistics 파이차트 통계' },
    { value: 'fa-solid fa-chart-bar', label: 'chart-bar data statistics 막대차트 통계' },
    { value: 'fa-solid fa-earth-americas', label: 'earth-americas world globe 지구 세계' },
    { value: 'fa-solid fa-map', label: 'map location travel 지도 위치' },
    { value: 'fa-solid fa-compass', label: 'compass direction travel 나침반 방향' },
    { value: 'fa-solid fa-sun', label: 'sun weather light 태양 해 날씨' },
    { value: 'fa-solid fa-moon', label: 'moon weather night 달 밤 날씨' },
    { value: 'fa-solid fa-snowflake', label: 'snowflake weather cold 눈 추위 날씨' },
    { value: 'fa-solid fa-fire', label: 'fire hot flame 불 열기' },
    { value: 'fa-solid fa-bolt', label: 'bolt lightning energy 번개 에너지' },
    { value: 'fa-solid fa-umbrella', label: 'umbrella rain weather 우산 비 날씨' },
    { value: 'fa-solid fa-leaf', label: 'leaf nature plant 나뭇잎 자연' },
    { value: 'fa-solid fa-tree', label: 'tree nature forest 나무 숲' },
    { value: 'fa-solid fa-fish', label: 'fish animal sea 물고기 바다' },
    { value: 'fa-solid fa-paw', label: 'paw animal pet dog cat 발자국 동물' },
    { value: 'fa-solid fa-brain', label: 'brain thinking mind 뇌 생각 지능' },
    { value: 'fa-solid fa-bomb', label: 'bomb explosive military 폭탄 군사' },
    { value: 'fa-solid fa-shield-halved', label: 'shield protection military 방패 보호 군사' },
    { value: 'fa-solid fa-flag', label: 'flag military goal 깃발 군사 목표' },
    { value: 'fa-solid fa-helicopter', label: 'helicopter air military 헬기 헬리콥터 군사' },
    { value: 'fa-solid fa-hat-wizard', label: 'wizard magic occult 마법사 모자 오컬트' },
    { value: 'fa-solid fa-wand-magic-sparkles', label: 'magic wand spell occult 지팡이 마법 주문' },
    { value: 'fa-solid fa-scroll', label: 'scroll magic spell occult 스크롤 마법 주문서' },
    { value: 'fa-solid fa-book-skull', label: 'book skull occult magic 마법서 해골 오컬트' },
    { value: 'fa-solid fa-crow', label: 'crow occult bird 까마귀 오컬트 조류' },
    { value: 'fa-solid fa-ghost', label: 'ghost occult spirit 유령 오컬트 영혼' },
    { value: 'fa-solid fa-skull', label: 'skull occult death 해골 오컬트 죽음' },
    { value: 'fa-brands fa-windows', label: 'windows os microsoft 윈도우 운영체제' },
    { value: 'fa-brands fa-apple', label: 'apple ios macos apple 애플 운영체제 아이폰 맥' },
    { value: 'fa-brands fa-linux', label: 'linux penguin os 리눅스 운영체제 펭귄' },
    { value: 'fa-brands fa-android', label: 'android os google 안드로이드 운영체제 구글' },
    { value: 'fa-brands fa-ubuntu', label: 'ubuntu linux os 우분투 리눅스 운영체제' },
    { value: 'fa-brands fa-docker', label: 'docker container dev os 도커 컨테이너 개발' },
    { value: 'fa-solid fa-torii-gate', label: 'torii shrine japan occult 신사 도리이 일본 오컬트' },
    { value: 'fa-solid fa-bowl-food', label: 'bowl food rice japan ramen bowl 식사 음식 일본 라멘' }
];

const COLOR_ICONS = [
    { value: '😀', label: 'grinning face happy 웃음 행복' },
    { value: '😃', label: 'smiley face happy 웃음 행복' },
    { value: '😄', label: 'smile face happy 웃음 행복' },
    { value: '😁', label: 'grin face happy 웃음 행복' },
    { value: '😆', label: 'laughing face happy 웃음 행복' },
    { value: '😅', label: 'sweat_smile face happy 땀 웃음' },
    { value: '😂', label: 'joy face happy 눈물 웃음' },
    { value: '🤣', label: 'rofl face happy 웃음' },
    { value: '😊', label: 'blush face happy 홍조 웃음' },
    { value: '😇', label: 'innocent face angel 천사' },
    { value: '🙂', label: 'slightly_smiling_face face 미소' },
    { value: '🙃', label: 'upside_down_face face 반전' },
    { value: '😉', label: 'wink face 윙크' },
    { value: '😌', label: 'relieved face 안도' },
    { value: '😍', label: 'heart_eyes face love 하트 사랑' },
    { value: '🥰', label: 'smiling_face_with_three_hearts face love 하트 사랑' },
    { value: '😘', label: 'kissing_heart face love 키스 사랑' },
    { value: '😗', label: 'kissing face 키스' },
    { value: '😙', label: 'kissing_smiling_eyes face 키스' },
    { value: '😚', label: 'kissing_closed_eyes face 키스' },
    { value: '😋', label: 'yum face food 맛있다' },
    { value: '😛', label: 'tongue face 메롱' },
    { value: '😝', label: 'stuck_out_tongue_closed_eyes face 메롱' },
    { value: '😜', label: 'stuck_out_tongue_winking_eye face 윙크 메롱' },
    { value: '🤪', label: 'zany_face face 미친' },
    { value: '🤨', label: 'raised_eyebrow face 의심' },
    { value: '🧐', label: 'monocle_face face 관찰' },
    { value: '🤓', label: 'nerd_face face 안경' },
    { value: '😎', label: 'sunglasses face 멋짐 선글라스' },
    { value: '🤩', label: 'star_struck face 별' },
    { value: '🥳', label: 'partying_face face party 파티' },
    { value: '😏', label: 'smirk face 비웃음' },
    { value: '😒', label: 'unamused face 지루함' },
    { value: '😞', label: 'disappointed face 실망' },
    { value: '😔', label: 'pensive face 생각' },
    { value: '😟', label: 'worried face 걱정' },
    { value: '😕', label: 'confused face 혼란' },
    { value: '🙁', label: 'slightly_frowning_face face 슬픔' },
    { value: '☹️', label: 'frowning_face face 슬픔' },
    { value: '😣', label: 'persevere face 인내' },
    { value: '😖', label: 'confounded face 당황' },
    { value: '😫', label: 'tired_face face 피곤' },
    { value: '😩', label: 'weary face 피곤' },
    { value: '🥺', label: 'pleading_face face 간절' },
    { value: '😢', label: 'cry face sad 눈물 슬픔' },
    { value: '😭', label: 'sob face sad 눈물 슬픔' },
    { value: '😤', label: 'triumph face anger 화남' },
    { value: '😠', label: 'angry face anger 화남' },
    { value: '😡', label: 'rage face anger 화남' },
    { value: '🤬', label: 'face_with_symbols_on_mouth face anger 욕설' },
    { value: '🤯', label: 'exploding_head face 충격' },
    { value: '😳', label: 'flushed face 당황' },
    { value: '🥵', label: 'hot_face face 더움' },
    { value: '🥶', label: 'cold_face face 추움' },
    { value: '😱', label: 'scream face fear 공포' },
    { value: '😨', label: 'fearful face fear 두려움' },
    { value: '😰', label: 'cold_sweat face fear 식은땀' },
    { value: '😥', label: 'disappointed_relieved face 안도 슬픔' },
    { value: '😓', label: 'sweat face 땀' },
    { value: '🤗', label: 'hugging_face face 포옹' },
    { value: '🤔', label: 'thinking_face face 생각' },
    { value: '🤭', label: 'face_with_hand_over_mouth face 웃음' },
    { value: '🤫', label: 'shushing_face face 조용' },
    { value: '🤥', label: 'lying_face face 거짓말' },
    { value: '😶', label: 'no_mouth face 말없음' },
    { value: '😐', label: 'neutral_face face 무표정' },
    { value: '😑', label: 'expressionless face 무표정' },
    { value: '😬', label: 'grimacing face 찡그림' },
    { value: '🙄', label: 'eye_roll face 한심' },
    { value: '😯', label: 'hushed face 놀람' },
    { value: '😦', label: 'frowning_face_with_open_mouth face 슬픔' },
    { value: '😧', label: 'anguished face 고통' },
    { value: '😮', label: 'open_mouth face 놀람' },
    { value: '😲', label: 'astonished face 놀람' },
    { value: '🥱', label: 'yawning_face face 하품' },
    { value: '😴', label: 'sleeping face 잠' },
    { value: '🤤', label: 'drooling_face face 침' },
    { value: '😪', label: 'sleepy face 졸림' },
    { value: '😵', label: 'dizzy_face face 어지러움' },
    { value: '🤐', label: 'zipper_mouth_face face 입다물기' },
    { value: '🥴', label: 'woozy_face face 취함' },
    { value: '🤢', label: 'nauseated_face face 구역질' },
    { value: '🤮', label: 'vomiting_face face 구토' },
    { value: '🤧', label: 'sneezing_face face 재채기' },
    { value: '😷', label: 'mask face 마스크' },
    { value: '🤒', label: 'face_with_thermometer face 아픔' },
    { value: '🤕', label: 'face_with_head_bandage face 부상' },
    { value: '🤑', label: 'money_mouth_face face 돈' },
    { value: '🤠', label: 'cowboy_hat_face face 카우보이' },
    { value: '😈', label: 'smiling_imp face devil 악마' },
    { value: '👿', label: 'imp face devil 악마' },
    { value: '👹', label: 'ogre 도깨비' },
    { value: '👺', label: 'goblin 고블린' },
    { value: '🤡', label: 'clown_face face 광대' },
    { value: '💩', label: 'poop 똥' },
    { value: '👻', label: 'ghost 유령' },
    { value: '💀', label: 'skull 해골' },
    { value: '☠️', label: 'skull_and_crossbones 해골' },
    { value: '👽', label: 'alien 외계인' },
    { value: '👾', label: 'alien_monster 몬스터' },
    { value: '🤖', label: 'robot 로봇' },
    { value: '🎃', label: 'jack_o_lantern 호박' },
    { value: '😺', label: 'smiley_cat cat 고양이' },
    { value: '😸', label: 'smile_cat cat 고양이' },
    { value: '😻', label: 'heart_eyes_cat cat 고양이' },
    { value: '😼', label: 'smirk_cat cat 고양이' },
    { value: '😽', label: 'kissing_cat cat 고양이' },
    { value: '🙀', label: 'scream_cat cat 고양이' },
    { value: '😿', label: 'crying_cat_face cat 고양이' },
    { value: '😾', label: 'pouting_cat cat 고양이' },
    { value: '🐶', label: 'dog 강아지' },
    { value: '🐱', label: 'cat 고양이' },
    { value: '🐭', label: 'mouse 쥐' },
    { value: '🐹', label: 'hamster 햄스터' },
    { value: '🐰', label: 'rabbit 토끼' },
    { value: '🦊', label: 'fox 여우' },
    { value: '🐻', label: 'bear 곰' },
    { value: '🐼', label: 'panda 판다' },
    { value: '🐻‍❄️', label: 'polar_bear 북극곰' },
    { value: '🐨', label: 'koala 코알라' },
    { value: '🐯', label: 'tiger 호랑이' },
    { value: '🦁', label: 'lion 사자' },
    { value: '🐮', label: 'cow 소' },
    { value: '🐷', label: 'pig 돼지' },
    { value: '🐽', label: 'pig_nose 돼지코' },
    { value: '🐸', label: 'frog 개구리' },
    { value: '🐵', label: 'monkey_face 원숭이' },
    { value: '🙈', label: 'see_no_evil 원숭이' },
    { value: '🙉', label: 'hear_no_evil 원숭이' },
    { value: '🙊', label: 'speak_no_evil 원숭이' },
    { value: '🐒', label: 'monkey 원숭이' },
    { value: '🐔', label: 'chicken 닭' },
    { value: '🐧', label: 'penguin 펭귄' },
    { value: '🐦', label: 'bird 새' },
    { value: '🐤', label: 'baby_chick 병아리' },
    { value: '🐣', label: 'hatching_chick 병아리' },
    { value: '🐥', label: 'front_facing_baby_chick 병아리' },
    { value: '🦆', label: 'duck 오리' },
    { value: '🦅', label: 'eagle 독수리' },
    { value: '🦉', label: 'owl 부엉이' },
    { value: '🦇', label: 'bat 박쥐' },
    { value: '🐺', label: 'wolf 늑대' },
    { value: '🐗', label: 'boar 멧돼지' },
    { value: '🐴', label: 'horse 말' },
    { value: '🦄', label: 'unicorn 유니콘' },
    { value: '🐝', label: 'bee 꿀벌' },
    { value: '🪱', label: 'worm 지렁이' },
    { value: '🐛', label: 'bug 벌레' },
    { value: '🦋', label: 'butterfly 나비' },
    { value: '🐌', label: 'snail 달팽이' },
    { value: '🐞', label: 'lady_beetle 무당벌레' },
    { value: '🐜', label: 'ant 개미' },
    { value: '🦟', label: 'mosquito 모기' },
    { value: '🦗', label: 'cricket 귀뚜라미' },
    { value: '🕷️', label: 'spider 거미' },
    { value: '🕸️', label: 'spider_web 거미줄' },
    { value: '🦂', label: 'scorpion 전갈' },
    { value: '🐢', label: 'turtle 거북이' },
    { value: '🐍', label: 'snake 뱀' },
    { value: '🦎', label: 'lizard 도마뱀' },
    { value: 'Rex', label: 't-rex 공룡' },
    { value: '🦕', label: 'sauropod 공룡' },
    { value: '🐙', label: 'octopus 문어' },
    { value: '🦑', label: 'squid 오징어' },
    { value: '🦐', label: 'shrimp 새우' },
    { value: '🦞', label: 'lobster 바닷가재' },
    { value: '🦀', label: 'crab 게' },
    { value: '🐡', label: 'blowfish 복어' },
    { value: '🐠', label: 'tropical_fish 물고기' },
    { value: '🐟', label: 'fish 물고기' },
    { value: '🐬', label: 'dolphin 돌고래' },
    { value: '🐳', label: 'spouting_whale 고래' },
    { value: '🐋', label: 'whale 고래' },
    { value: '🦈', label: 'shark 상어' },
    { value: '🐊', label: 'crocodile 악어' },
    { value: '🐅', label: 'tiger 호랑이' },
    { value: '🐆', label: 'leopard 표범' },
    { value: '🦓', label: 'zebra 얼룩말' },
    { value: '🦍', label: 'gorilla 고릴라' },
    { value: '🦧', label: 'orangutan 오랑우탄' },
    { value: '🐘', label: 'elephant 코끼리' },
    { value: '🦛', label: 'hippopotamus 하마' },
    { value: '🦏', label: 'rhinoceros 코뿔소' },
    { value: '🐪', label: 'camel 낙타' },
    { value: '🐫', label: 'two_hump_camel 낙타' },
    { value: '🦒', label: 'giraffe 기린' },
    { value: '🦘', label: 'kangaroo 캥거루' },
    { value: '🐃', label: 'water_buffalo 버팔로' },
    { value: '🐂', label: 'ox 황소' },
    { value: '🐄', label: 'cow 젖소' },
    { value: '🐎', label: 'horse 말' },
    { value: '🐖', label: 'pig 돼지' },
    { value: ' ram', label: 'ram 양' },
    { value: '🐑', label: 'sheep 양' },
    { value: '🐐', label: 'goat 염소' },
    { value: '🦌', label: 'deer 사슴' },
    { value: '🐕', label: 'dog 개' },
    { value: '🐩', label: 'poodle 푸들' },
    { value: '🦮', label: 'guide_dog 안내견' },
    { value: '🐕‍🦺', label: 'service_dog 봉사견' },
    { value: '🐈', label: 'cat 고양이' },
    { value: '🐈‍⬛', label: 'black_cat 검은고양이' },
    { value: '🐓', label: 'rooster 수탉' },
    { value: '🦃', label: 'turkey 칠면조' },
    { value: '🦚', label: 'peacock 공작' },
    { value: '🦜', label: 'parrot 앵무새' },
    { value: '🦢', label: 'swan 백조' },
    { value: '🦩', label: 'flamingo 홍학' },
    { value: '🕊️', label: 'dove 비둘기' },
    { value: '🐇', label: 'rabbit 토끼' },
    { value: '🦝', label: 'raccoon 너구리' },
    { value: '🦨', label: 'skunk 스컹크' },
    { value: '🦡', label: 'badger 오소리' },
    { value: '🦦', label: 'otter 수달' },
    { value: '🦥', label: 'sloth 나무늘보' },
    { value: '🐁', label: 'mouse 생쥐' },
    { value: ' rat', label: 'rat 쥐' },
    { value: '🐿️', label: 'chipmunk 다람쥐' },
    { value: '🦔', label: 'hedgehog 고슴도치' },
    { value: '🍏', label: 'green_apple fruit 사과' },
    { value: '🍎', label: 'red_apple fruit 사과' },
    { value: '🍐', label: 'pear fruit 배' },
    { value: '🍊', label: 'tangerine fruit 귤' },
    { value: '🍋', label: 'lemon fruit 레몬' },
    { value: '🍌', label: 'banana fruit 바나나' },
    { value: '🍉', label: 'watermelon fruit 수박' },
    { value: '🍇', label: 'grapes fruit 포도' },
    { value: '🍓', label: 'strawberry fruit 딸기' },
    { value: '🫐', label: 'blueberries fruit 블루베리' },
    { value: '🍈', label: 'melon fruit 멜론' },
    { value: '🍒', label: 'cherries fruit 체리' },
    { value: '🍑', label: 'peach fruit 복숭아' },
    { value: '🥭', label: 'mango fruit 망고' },
    { value: '🍍', label: 'pineapple fruit 파인애플' },
    { value: '🥥', label: 'coconut fruit 코코넛' },
    { value: '🥝', label: 'kiwi_fruit fruit 키위' },
    { value: '🍅', label: 'tomato vegetable 토마토' },
    { value: '🍆', label: 'eggplant vegetable 가지' },
    { value: '🥑', label: 'avocado vegetable 아보카도' },
    { value: '🥦', label: 'broccoli vegetable 브로콜리' },
    { value: '🥬', label: 'leafy_green vegetable 야채' },
    { value: '🥒', label: 'cucumber vegetable 오이' },
    { value: '🌶️', label: 'hot_pepper vegetable 고추' },
    { value: '🫑', label: 'bell_pepper vegetable 피망' },
    { value: '🌽', label: 'corn vegetable 옥수수' },
    { value: '🥕', label: 'carrot vegetable 당근' },
    { value: '🫒', label: 'olive 올리브' },
    { value: '🧄', label: 'garlic vegetable 마늘' },
    { value: '🧅', label: 'onion vegetable 양파' },
    { value: '🥔', label: 'potato vegetable 감자' },
    { value: '🍠', label: 'roasted_sweet_potato 고구마' },
    { value: '🥐', label: 'croissant bread 크로와상' },
    { value: '🥯', label: 'bagel bread 베이글' },
    { value: '🍞', label: 'bread 빵' },
    { value: '🥖', label: 'baguette_bread 바게트' },
    { value: '🥨', label: 'pretzel 프레첼' },
    { value: '🧀', label: 'cheese 치즈' },
    { value: '🥚', label: 'egg 계란' },
    { value: '🍳', label: 'cooking 계란후라이' },
    { value: '🧈', label: 'butter 버터' },
    { value: '🥞', label: 'pancakes 팬케이크' },
    { value: '🧇', label: 'waffle 와플' },
    { value: '🥓', label: 'bacon 베이컨' },
    { value: '🥩', label: 'meat 스테이크' },
    { value: '🍗', label: 'poultry_leg 치킨' },
    { value: '🍖', label: 'meat_on_bone 고기' },
    { value: '🦴', label: 'bone 뼈' },
    { value: '🌭', label: 'hotdog 핫도그' },
    { value: '🍔', label: 'hamburger 햄버거' },
    { value: '🍟', label: 'french_fries 감자튀김' },
    { value: '🍕', label: 'pizza 피자' },
    { value: '🫓', label: 'flatbread 빵' },
    { value: '🥪', label: 'sandwich 샌드위치' },
    { value: '🥙', label: 'stuffed_flatbread' },
    { value: '🧆', label: 'falafel' },
    { value: '🌮', label: 'taco 타코' },
    { value: '🌯', label: 'burrito 브리또' },
    { value: '🫔', label: 'tamale' },
    { value: '🥗', label: 'green_salad 샐러드' },
    { value: '🥘', label: 'shallow_pan_of_food' },
    { value: '🫕', label: 'fondue 퐁듀' },
    { value: '🥣', label: 'bowl_with_spoon' },
    { value: '🍝', label: 'spaghetti 스파게티' },
    { value: '🍜', label: 'steaming_bowl ramen japan 라면 일본' },
    { value: '🍲', label: 'pot_of_food' },
    { value: '🍛', label: 'curry_rice japan 카레 일본' },
    { value: '🍣', label: 'sushi japan 초밥 일본' },
    { value: '🍱', label: 'bento_box japan 도시락 일본' },
    { value: '🥟', label: 'dumpling 만두' },
    { value: '🦪', label: 'oyster 굴' },
    { value: '🍤', label: 'fried_shrimp japan 새우튀김 일본' },
    { value: '🍙', label: 'rice_ball japan 주먹밥 일본' },
    { value: '🍚', label: 'cooked_rice 밥' },
    { value: '🍘', label: 'rice_cracker japan 쌀과자 일본' },
    { value: '🍡', label: 'dango japan 경단 일본' },
    { value: '🍢', label: 'oden japan 어묵 일본' },
    { value: '🍦', label: 'soft_ice_cream 아이스크림' },
    { value: '🍧', label: 'shaved_ice japan 빙수 일본' },
    { value: '🍨', label: 'ice_cream 아이스크림' },
    { value: '🍩', label: 'doughnut 도넛' },
    { value: '🍪', label: 'cookie 쿠키' },
    { value: '🎂', label: 'birthday_cake 케이크' },
    { value: '🍰', label: 'shortcake 조각케이크' },
    { value: '🧁', label: 'cupcake 컵케이크' },
    { value: '🥧', label: 'pie 파이' },
    { value: '🍫', label: 'chocolate_bar 초콜릿' },
    { value: '🍬', label: 'candy 사탕' },
    { value: '🍭', label: 'lollipop 사탕' },
    { value: '🍮', label: 'custard 푸딩' },
    { value: '🍯', label: 'honey_pot 꿀' },
    { value: '🍼', label: 'baby_bottle 젖병' },
    { value: '🥛', label: 'glass_of_milk 우유' },
    { value: '☕', label: 'coffee 커피' },
    { value: '🫖', label: 'teapot 차' },
    { value: '🍵', label: 'teacup_without_handle japan tea 차 일본' },
    { value: '🍶', label: 'sake japan alcohol 사케 일본 술' },
    { value: '🍾', label: 'bottle_with_popping_cork 샴페인' },
    { value: '🍷', label: 'wine_glass 와인' },
    { value: '🍸', label: 'cocktail_glass 칵테일' },
    { value: '🍹', label: 'tropical_drink 주스' },
    { value: '🍺', label: 'beer_mug 맥주' },
    { value: '🍻', label: 'clinking_beer_mugs 맥주' },
    { value: '🥂', label: 'clinking_glasses 건배' },
    { value: '🥃', label: 'tumbler_glass 위스키' },
    { value: '🥤', label: 'cup_with_straw 음료수' },
    { value: '🧋', label: 'bubble_tea 버블티' },
    { value: '🧃', label: 'beverage_box 주스' },
    { value: '🧉', label: 'mate' },
    { value: '🧊', label: 'ice 얼음' },
    { value: '🧠', label: 'brain 뇌 생각 지능' },
    { value: '🪖', label: 'military_helmet 군사 헬멧 철모' },
    { value: '🎖️', label: 'military_medal 훈장 군사' },
    { value: '🔫', label: 'pistol gun 총 무기' },
    { value: '💣', label: 'bomb 폭탄' },
    { value: '🛡️', label: 'shield 방패 보호' },
    { value: '⚔️', label: 'crossed_swords 칼 싸움 군사' },
    { value: '🗡️', label: 'dagger 단검 칼' },
    { value: '🏹', label: 'bow_and_arrow 활 화살' },
    { value: '🚁', label: 'helicopter 헬기 헬리콥터' },
    { value: '🛰️', label: 'satellite 인공위성' },
    { value: '🚩', label: 'triangular_flag 깃발 국기' },
    { value: '🏳️', label: 'white_flag 백기 항복' },
    { value: '🏴', label: 'black_flag 깃발' },
    { value: '🏴‍☠️', label: 'pirate_flag 해적기' },
    { value: '🔮', label: 'crystal_ball occult magic fortune 수정구 오컬트 마법 점술' },
    { value: '🧿', label: 'nazar_amulet evil_eye protection 나자르 본주 나쁜눈 보호' },
    { value: '🪬', label: 'hamsa eye hand protection 함사 손 보호' },
    { value: '🕯️', label: 'candle occult light ritual 양초 오컬트 의식' },
    { value: '🪄', label: 'magic_wand spell occult 지팡이 마법 주문' },
    { value: '🪞', label: 'mirror occult magic 거울 오컬트' },
    { value: '🧪', label: 'potion magic alchemy 포션 마법 연금술' },
    { value: '✨', label: 'sparkles magic occult 반짝임 마법' },
    { value: '🧙', label: 'mage witch wizard magic 마법사 마녀' },
    { value: '🌕', label: 'full_moon occult night 보름달 오컬트 밤' },
    { value: '🇯🇵', label: 'japan flag 국기 일본' },
    { value: '🗾', label: 'japan map 지도 일본' },
    { value: '🗻', label: 'mount_fuji fuji japan 후지산 일본' },
    { value: '🗼', label: 'tokyo_tower tower japan 도쿄타워 일본' },
    { value: '🏯', label: 'japanese_castle castle japan 성 일본' },
    { value: '⛩️', label: 'shinto_shrine torii shrine japan occult 신사 도리이 일본 오컬트' },
    { value: '🏮', label: 'izakaya lantern japan occult 이자카야 등불 일본 오컬트' },
    { value: '🎎', label: 'japanese_dolls dolls japan 인형 일본' },
    { value: '🎏', label: 'carp_streamer koinobori japan 잉어 깃발 일본' },
    { value: '🎐', label: 'wind_chime furin japan 풍경 일본' },
    { value: '🎋', label: 'tanabata_tree tree japan 타나바타 일본' },
    { value: '🍥', label: 'fish_cake japan 어묵 일본' },
    { value: '🥋', label: 'martial_arts_uniform judo karate japan 도복 유도 가라테 일본' },
    { value: '👘', label: 'kimono japan 기모노 일본' }
];

let state = {
    currentPageId: null,
    currentTab: 'theme', 
    appState: null,
    searchQuery: ''
};

export function initIconPicker(appState) {
    state.appState = appState;
    
    const modal = document.getElementById('icon-picker-modal');
    if (!modal) return;

    document.getElementById('close-icon-picker-btn')?.addEventListener('click', () => {
        toggleModal(modal, false);
    });

    modal.querySelector('.modal-overlay')?.addEventListener('click', () => {
        toggleModal(modal, false);
    });

    document.getElementById('icon-tab-theme')?.addEventListener('click', () => {
        switchTab('theme');
    });

    document.getElementById('icon-tab-color')?.addEventListener('click', () => {
        switchTab('color');
    });

    document.getElementById('remove-icon-btn')?.addEventListener('click', () => {
        selectIcon(null);
    });

    const searchInput = document.getElementById('icon-picker-search');
    searchInput?.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.toLowerCase().trim();
        renderIconGrid();
    });
}

export function showIconPickerModal(pageId) {
    state.currentPageId = pageId;
    const modal = document.getElementById('icon-picker-modal');
    if (!modal) return;

    state.searchQuery = '';
    const searchInput = document.getElementById('icon-picker-search');
    if (searchInput) searchInput.value = '';

    switchTab('theme'); 
    toggleModal(modal, true);
    
    setTimeout(() => searchInput?.focus(), 100);
}

function switchTab(tab) {
    state.currentTab = tab;
    
    const themeBtn = document.getElementById('icon-tab-theme');
    const colorBtn = document.getElementById('icon-tab-color');
    
    if (tab === 'theme') {
        themeBtn?.classList.add('active');
        colorBtn?.classList.remove('active');
    } else {
        themeBtn?.classList.remove('active');
        colorBtn?.classList.add('active');
    }
    
    renderIconGrid();
}

function renderIconGrid() {
    const grid = document.getElementById('icon-picker-grid');
    if (!grid) return;

    grid.innerHTML = '';
    const icons = state.currentTab === 'theme' ? THEME_ICONS : COLOR_ICONS;
    
    const filteredIcons = icons.filter(icon => {
        if (!state.searchQuery) return true;
        return icon.label.toLowerCase().includes(state.searchQuery) || 
               icon.value.toLowerCase().includes(state.searchQuery);
    });

    if (filteredIcons.length === 0) {
        const noResults = document.createElement('div');
        noResults.className = 'no-results';
        noResults.style.gridColumn = '1 / -1';
        noResults.style.textAlign = 'center';
        noResults.style.padding = '40px';
        noResults.style.color = '#9ca3af';
        noResults.textContent = '검색 결과가 없습니다.';
        grid.appendChild(noResults);
        return;
    }

    if (state.searchQuery) {
        grid.classList.add('search-results-list');
    } else {
        grid.classList.remove('search-results-list');
    }

    filteredIcons.forEach(icon => {
        const btn = document.createElement('button');
        btn.className = 'icon-picker-item';
        btn.type = 'button';
        btn.title = icon.label;

        const iconContainer = document.createElement('div');
        iconContainer.className = 'icon-picker-item-icon';
        if (state.currentTab === 'theme') {
            addIcon(iconContainer, icon.value);
        } else {
            iconContainer.textContent = icon.value;
        }
        btn.appendChild(iconContainer);

        if (state.searchQuery) {
            const labelSpan = document.createElement('span');
            labelSpan.className = 'icon-picker-item-label';
            labelSpan.textContent = icon.label;
            btn.appendChild(labelSpan);
        }

        btn.addEventListener('click', () => {
            selectIcon(icon.value);
        });

        grid.appendChild(btn);
    });
}

async function selectIcon(iconValue) {
    if (!state.currentPageId) return;

    try {
        await api.put(`/api/pages/${encodeURIComponent(state.currentPageId)}`, {
            icon: iconValue
        });

        if (state.appState && state.appState.pages) {
            const page = state.appState.pages.find(p => p.id === state.currentPageId);
            if (page) {
                page.icon = iconValue;
            }
        }

        if (typeof window.renderPageList === 'function') {
            window.renderPageList();
        } else if (state.appState && typeof state.appState.renderPageList === 'function') {
            state.appState.renderPageList();
        } else {
            if (state.appState && typeof state.appState.fetchPageList === 'function') {
                await state.appState.fetchPageList();
            }
        }

        toggleModal('#icon-picker-modal', false);
    } catch (error) {
        console.error('Failed to set icon:', error);
        alert('아이콘 설정 실패: ' + error.message);
    }
}
