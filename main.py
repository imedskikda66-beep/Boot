import telebot
import requests
import socket
import time
import concurrent.futures
import re
from telebot.types import ReplyKeyboardMarkup, KeyboardButton

# توكن البوت
bot = telebot.TeleBot("8420676859:AAGQ6ZgnTuUs648v_79hR_CEIw6VUqRE2B4")

# متغيرات التحكم في الفحص
scanning_active = {}
current_results = {}
user_operations = {}
waiting_proxy_url = set()

# ========== الدوال الأساسية ==========
def create_stop_keyboard():
    keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
    keyboard.add(KeyboardButton("⏹️ إيقاف الفحص"))
    return keyboard

def create_main_keyboard():
    keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
    keyboard.add(KeyboardButton("📋 فحص بروكسيات"))
    keyboard.add(KeyboardButton("📁 رفع ملف txt"))
    keyboard.add(KeyboardButton("🌐 فحص عبر الرابط"))
    return keyboard

def stop_user_operations(chat_id):
    """إيقاف أي عملية جارية للمستخدم بشكل آمن"""
    if chat_id in user_operations:
        user_operations[chat_id]['stop'] = True
    waiting_proxy_url.discard(chat_id)
    if chat_id in scanning_active:
        scanning_active[chat_id] = False

def should_stop(chat_id):
    """تعيد True إذا كان المستخدم قد طلب إيقاف أي عملية جارية"""
    return user_operations.get(chat_id, {}).get('stop', False)

def extract_ip_port(proxy_text):
    """استخراج IP و PORT من النص - محسن لدعم الروابط"""
    try:
        proxy_text = proxy_text.strip()
        proxy_text = re.sub(r'^(http|https|socks|socks5)://', '', proxy_text)
        
        if ':' in proxy_text:
            parts = proxy_text.split(':')
            if len(parts) >= 2:
                host = parts[0].strip()
                port = int(parts[1].strip())
                
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                    try:
                        host = socket.gethostbyname(host)
                    except:
                        return None, None
                
                if 1 <= port <= 65535:
                    return host, port
        return None, None
    except:
        return None, None

def get_detailed_ip_info(ip):
    """الحصول على معلومات مفصلة عن الـ IP"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        
        country = data.get('country', 'Unknown')
        region = data.get('region', 'Unknown')
        city = data.get('city', 'Unknown')
        org = data.get('org', 'Unknown')
        
        if 'AS' in org:
            asn = org.split(' ')[0]
            isp = ' '.join(org.split(' ')[1:]) if len(org.split(' ')) > 1 else org
        else:
            asn = "ASUnknown"
            isp = org
        
        return {
            'country': country,
            'region': region, 
            'city': city,
            'asn': asn,
            'isp': isp,
        }
        
    except Exception as e:
        return {
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown', 
            'asn': 'ASUnknown',
            'isp': 'Unknown'
        }

def analyze_asn_risk(asn, isp):
    """تحليل مستوى خطر ASN"""
    risk_factors = {
        'high_risk': ['Google', 'Amazon', 'Microsoft', 'Cloudflare', 'Facebook'],
        'medium_risk': ['OVH', 'DigitalOcean', 'Linode', 'Vultr', 'Hetzner'],
    }
    
    asn_lower = str(asn).lower()
    isp_lower = str(isp).lower()
    
    for company in risk_factors['high_risk']:
        if company.lower() in asn_lower or company.lower() in isp_lower:
            return 'high'
    
    for company in risk_factors['medium_risk']:
        if company.lower() in asn_lower or company.lower() in isp_lower:
            return 'medium'
    
    return 'low'

def get_risk_icon(risk_level):
    icons = {
        'high': '🔴🚨',
        'medium': '🟡⚠️', 
        'low': '⚪'
    }
    return icons.get(risk_level, '⚪')

def check_single_proxy(proxy_text, user_id):
    """فحص بروكسي واحد مع معلومات مفصلة"""
    if should_stop(user_id):
        return None, "⏹️ تم إيقاف الفحص"
    
    ip, port = extract_ip_port(proxy_text)
    if not ip or not port:
        return None, "❌ تنسيق غير صحيح"
    
    try:
        ip_info = get_detailed_ip_info(ip)
        risk_level = analyze_asn_risk(ip_info['asn'], ip_info['isp'])
        risk_icon = get_risk_icon(risk_level)
        
        results = {
            'ip': ip, 'port': port, 'http': '❌', 'https': '❌', 'connect': '❌',
            'is_working': False, 'response_time': 0, 'text': proxy_text,
            'country': ip_info['country'], 'region': ip_info['region'], 
            'city': ip_info['city'], 'asn': ip_info['asn'], 'isp': ip_info['isp'],
            'risk_level': risk_level, 'risk_icon': risk_icon,
            'is_google': 'Google' in ip_info['isp'] or 'AS396982' in ip_info['asn']
        }
        
        # فحص CONNECT
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            connect_time = round((time.time() - start_time) * 1000, 2)
            
            if result == 0:
                results['connect'] = '✅'
                results['is_working'] = True
                results['response_time'] = connect_time
                sock.close()
                return results, None
            sock.close()
        except: pass
        
        # فحص HTTP
        try:
            start_time = time.time()
            proxy_dict = {'http': f"http://{ip}:{port}"}
            response = requests.get('http://httpbin.org/ip', proxies=proxy_dict, timeout=4)
            if response.status_code == 200:
                results['http'] = '✅'
                results['is_working'] = True
                results['response_time'] = round((time.time() - start_time) * 1000, 2)
                return results, None
        except: pass
        
        # فحص HTTPS
        try:
            start_time = time.time()
            proxy_dict = {'https': f"https://{ip}:{port}"}
            response = requests.get('https://httpbin.org/ip', proxies=proxy_dict, timeout=4, verify=False)
            if response.status_code == 200:
                results['https'] = '✅'
                results['is_working'] = True
                results['response_time'] = round((time.time() - start_time) * 1000, 2)
        except: pass
        
        return results if results['is_working'] else None, None
            
    except Exception as e:
        return None, f"❌ خطأ في الفحص: {str(e)}"

def format_proxy_result(proxy, index):
    """تنسيق نتيجة البروكسي بشكل مختصر"""
    google_flag = "🔴🚨" if proxy['is_google'] else proxy['risk_icon']
    response_time = f"⚡ {proxy['response_time']}ms" if proxy['response_time'] > 0 else ""
    
    protocol_port = ""
    if proxy['http'] == '✅': protocol_port = f"HTTP✅{proxy['port']}"
    elif proxy['https'] == '✅': protocol_port = f"HTTPS✅{proxy['port']}" 
    elif proxy['connect'] == '✅': protocol_port = f"CONNECT✅{proxy['port']}"
    
    return f"""
{index}. **{proxy['ip']}:{proxy['port']}** {google_flag}
   🌍 **البلد:** {proxy['country']}
   🏢 **المزود:** {proxy['isp']}
   🆔 **ASN:** {proxy['asn']}
   {response_time} • {protocol_port}
    """

def check_proxies_list(proxies_list, user_id, chat_id, bot):
    """فحص قائمة بروكسيات مع تحديث التقدم - الإصدار النهائي"""
    working_proxies = []
    google_proxies = []
    
    total = len(proxies_list)
    checked = 0
    working = 0
    
    # إرسال رسالة التقدم الأولى
    progress_message = bot.send_message(chat_id, "⏳ بدء الفحص...", reply_markup=create_stop_keyboard())
    
    # فحص تسلسلي بسيط مع تحديث العداد
    for proxy in proxies_list:
        if should_stop(user_id):
            break
            
        proxy_data, error = check_single_proxy(proxy, user_id)
        checked += 1
        
        if proxy_data:
            working += 1
            working_proxies.append(proxy_data)
            if proxy_data['is_google']:
                google_proxies.append(proxy_data)
        
        # تحديث العداد بعد كل بروكسي
        progress = (checked / total) * 100
        progress_bar = "🟢" * int(progress / 10) + "⚪" * (10 - int(progress / 10))
        
        progress_text = f"""
⏳ جاري الفحص...
{progress_bar} {progress:.1f}%

📊 التقدم:
• 📋 الإجمالي: {total}
• 🔍 تم فحص: {checked}
• ✅ الشغالة: {working}
• ⏳ المتبقي: {total - checked}
        """
        
        try:
            bot.edit_message_text(progress_text, chat_id, progress_message.message_id, reply_markup=create_stop_keyboard())
        except:
            pass
        
        time.sleep(0.05)  # وقت بسيط بين كل فحص
    
    return working_proxies, google_proxies

def fetch_proxies_from_url(url):
    """جلب البروكسيات من رابط"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        proxies = []
        for line in response.text.split('\n'):
            line = line.strip()
            if ':' in line and any(c.isdigit() for c in line):
                parts = line.split(':')
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    port = parts[1].strip()
                    if ip and port.isdigit():
                        proxies.append(f"{ip}:{port}")
        return proxies
    except Exception as e:
        print(f"Error fetching proxies from URL: {e}")
        return []

def process_custom_proxies_scan(chat_id, custom_url):
    """جلب البروكسيات من رابط وفحصها تلقائيًا"""
    user_operations[chat_id] = {'stop': False}
    
    progress_msg = bot.send_message(chat_id, "🔍 **جاري جلب البروكسيات...**")
    
    if should_stop(chat_id):
        return
    
    proxies = fetch_proxies_from_url(custom_url)
    if not proxies:
        bot.send_message(chat_id, "❌ لم يتم العثور على بروكسيات")
        return
    
    if should_stop(chat_id):
        return
    
    bot.edit_message_text(
        f"🌐 **تم جلب {len(proxies)} بروكسي**\n🚀 **بدء الفحص...**", 
        chat_id, progress_msg.message_id
    )
    
    process_scan_request_with_list(chat_id, proxies)

# ========== معالجات البوت ==========
@bot.message_handler(commands=['start'])
def send_welcome(message):
    welcome_text = """
🚀 أهلاً بك في بوت فحص البروكسيات الذكي!

⚡ المميزات:
• فحص HTTP/HTTPS/CONNECT
• معلومات مفصلة لكل بروكسي
• كشف بروكسيات Google النادرة 🚨
• دعم الروابط والمجالس
• رفع ملفات txt
• إيقاف فوري أثناء الفحص

📝 اختر أحد الخيارات:
    """
    bot.send_message(message.chat.id, welcome_text, reply_markup=create_main_keyboard())

@bot.message_handler(func=lambda message: message.text == "📋 فحص بروكسيات")
def scan_button(message):
    msg = bot.send_message(message.chat.id, 
                          "📋 أرسل قائمة البروكسيات (واحد أو أكثر في كل سطر)\n\n"
                          "📝 يدعم:\n• IP:Port\n• روابط\n• دومينات", 
                          reply_markup=create_main_keyboard())
    bot.register_next_step_handler(msg, process_scan_request)

@bot.message_handler(func=lambda message: message.text == "📁 رفع ملف txt")
def upload_file(message):
    msg = bot.send_message(message.chat.id, 
                          "📁 أرسل ملف txt يحتوي على قائمة البروكسيات", 
                          reply_markup=create_main_keyboard())
    bot.register_next_step_handler(msg, process_file_upload)

@bot.message_handler(func=lambda message: message.text == "🌐 فحص عبر الرابط")
def handle_proxy_url_request(message):
    chat_id = message.chat.id
    waiting_proxy_url.add(chat_id)
    bot.send_message(chat_id, "🔗 أرسل الرابط الذي يحتوي على قائمة البروكسيات\n\nمثال:\nhttps://example.com/socks5.txt")

@bot.message_handler(func=lambda message: message.chat.id in waiting_proxy_url)
def handle_proxy_url_input(message):
    chat_id = message.chat.id
    waiting_proxy_url.discard(chat_id)
    
    url = message.text.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    process_custom_proxies_scan(chat_id, url)

@bot.message_handler(func=lambda message: message.text == "⏹️ إيقاف الفحص")
def stop_scan(message):
    chat_id = message.chat.id
    stop_user_operations(chat_id)
    bot.send_message(chat_id, "⏹️ تم إيقاف الفحص - جاري جمع النتائج...", reply_markup=create_main_keyboard())

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if message.document.mime_type == 'text/plain' or message.document.file_name.endswith('.txt'):
        try:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            file_content = downloaded_file.decode('utf-8')
            proxies_list = [line.strip() for line in file_content.split('\n') if line.strip()]
            
            if not proxies_list:
                bot.send_message(message.chat.id, "❌ الملف فارغ")
                return
            
            bot.send_message(message.chat.id, f"📁 تم استلام {len(proxies_list)} بروكسي من الملف")
            process_scan_request_with_list(message.chat.id, proxies_list)
            
        except Exception as e:
            bot.send_message(message.chat.id, f"❌ خطأ في قراءة الملف: {str(e)}")
    else:
        bot.send_message(message.chat.id, "❌ يرجى رفع ملف txt فقط")

def process_file_upload(message):
    if message.document:
        handle_document(message)
    else:
        bot.send_message(message.chat.id, "❌ يرجى رفع ملف txt صالح")

def process_scan_request_with_list(chat_id, proxies_list):
    user_id = chat_id
    user_operations[user_id] = {'stop': False}
    
    try:
        scanning_active[user_id] = True
        bot.send_message(chat_id, f"🔍 بدء فحص {len(proxies_list)} بروكسي...", reply_markup=create_stop_keyboard())
        
        working_proxies, google_proxies = check_proxies_list(proxies_list, user_id, chat_id, bot)
        send_final_results(bot, chat_id, user_id, len(proxies_list), working_proxies, google_proxies)
            
    except Exception as e:
        bot.send_message(chat_id, f"❌ حدث خطأ: {str(e)}")
    finally:
        if user_id in scanning_active:
            scanning_active[user_id] = False
        if user_id in user_operations:
            del user_operations[user_id]

def process_scan_request(message):
    chat_id = message.chat.id
    
    try:
        text = message.text.strip()
        proxies_list = []
        for line in text.split('\n'):
            for item in line.split(','):
                for proxy in item.split():
                    if ':' in proxy:
                        proxies_list.append(proxy.strip())
        
        if not proxies_list:
            bot.send_message(chat_id, "❌ لم يتم العثور على بروكسيات صالحة")
            return
        
        process_scan_request_with_list(chat_id, proxies_list)
            
    except Exception as e:
        bot.send_message(chat_id, f"❌ حدث خطأ: {str(e)}")

def send_final_results(bot, chat_id, user_id, total_proxies, working_proxies, google_proxies):
    if not working_proxies:
        bot.send_message(chat_id, "❌ لا توجد بروكسيات شغالة", reply_markup=create_main_keyboard())
        return
    
    if should_stop(user_id) and working_proxies:
        result_text = f"⏹️ **تم إيقاف الفحص**\n\n📊 **النتائج حتى الآن:**\n• ✅ الشغالة: {len(working_proxies)}\n• 🚨 Google: {len(google_proxies)}\n"
    else:
        result_text = f"📊 **نتائج الفحص** • تم فحص {total_proxies} بروكسي\n\n✅ **الشغالة:** {len(working_proxies)}\n🚨 **Google:** {len(google_proxies)}\n⚡ **النسبة:** {(len(working_proxies)/total_proxies)*100:.1f}%\n"
    
    if google_proxies:
        alert_text = f"🚨 **تم العثور على {len(google_proxies)} بروكسي Google** 🔴🚨\n\n"
        for i, proxy in enumerate(google_proxies, 1):
            alert_text += format_proxy_result(proxy, i)
        bot.send_message(chat_id, alert_text)
    
    for i, proxy in enumerate(working_proxies, 1):
        result_text += format_proxy_result(proxy, i)
    
    if len(result_text) > 4096:
        parts = [result_text[i:i+4096] for i in range(0, len(result_text), 4096)]
        for part in parts:
            bot.send_message(chat_id, part, reply_markup=create_main_keyboard())
    else:
        bot.send_message(chat_id, result_text, reply_markup=create_main_keyboard())

@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    chat_id = message.chat.id
    text = message.text
    
    if ':' in text and any(char.isdigit() for char in text) and text not in ["📋 فحص بروكسيات", "⏹️ إيقاف الفحص", "📁 رفع ملف txt", "🌐 فحص عبر الرابط"]:
        process_scan_request(message)
    elif text not in ["📋 فحص بروكسيات", "⏹️ إيقاف الفحص", "📁 رفع ملف txt", "🌐 فحص عبر الرابط"]:
        bot.send_message(chat_id, "📝 اختر أحد الخيارات من الأزرار", reply_markup=create_main_keyboard())

if __name__ == "__main__":
    print("🟢 بدء تشغيل بوت فحص البروكسيات النهائي...")
    print("⚡ المميزات: عداد عامل، إيقاف فوري، فحص روابط")
    bot.infinity_polling()
