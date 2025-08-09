# Django + React Projesi Başlatma Kılavuzu
Bu doküman, Django backend ve React frontend kullanan tam yığın bir projeyi nasıl kurup çalıştıracağınızı adım adım açıklamaktadır. Backend API yapısı, frontend bileşenleri ve temel entegrasyon detayları basit bir şekilde ele alınmıştır.

---


# **🧠 BACKEND -> DJANGO**


<div align = center >
  <img src = 'https://github.com/user-attachments/assets/e7bcfe47-3c30-4c6a-8852-272f48088659' width=40% >
</div>


# 1. Komutlar

## 1. Sanal Ortamın Hazırlanması

Bir sanal ortam oluşturmak için terminalde aşağıdaki komutu çalıştırın:

```bash
python -m venv env  
```

Bu komut, projenizin kök dizininde `env` adlı bir klasör oluşturur ve proje bağımlılıklarının izole bir şekilde yönetilmesini sağlar.

---

## 2. Sanal Ortamı Aktifleştirme

Oluşturduğunuz sanal ortamı aktif hale getirmek için aşağıdaki komutu kullanın:

```bash
env\Scripts\activate  
```

---

## 3. Gerekli kütüphaneleri yükleyelim

Proje dizininde bir `requirements.txt` dosyası oluşturun ve aşağıdaki kütüphaneleri içine ekleyin:

```txt
asgiref  
Django  
django-cors-headers  
djangorestframework  
djangorestframework_simplejwt  
psycopg2-binary  
PyJWT  
python-dotenv  
pytz  
sqlparse  
tzdata  
```

Daha sonra terminalde şu komutu çalıştırarak bu kütüphaneleri yükleyin:

```bash
pip install -r requirements.txt  
```

---

### 📦 `requirements.txt` içindeki kütüphanelerin açıklamaları:

* **asgiref**: Django’nun asenkron özellikleri için altyapı sağlar (ASGI desteği).
* **Django**: Web uygulamanın temel çatısını oluşturur.
* **django-cors-headers**: Frontend ve backend farklı portlarda çalışırken oluşan CORS hatalarını engeller.
* **djangorestframework**: Django ile RESTful API’ler oluşturmanı sağlar.
* **djangorestframework\_simplejwt**: JWT kullanarak kullanıcı girişi ve oturum yönetimi yapmanı sağlar.
* **psycopg2-binary**: PostgreSQL veritabanı ile bağlantı kurmak için gereklidir.
* **PyJWT**: JWT token'larını üretir ve doğrular.
* **python-dotenv**: `.env` dosyasındaki gizli bilgileri (anahtar, URL vs.) projenin içine alır.
* **pytz**: Zaman dilimlerini yönetir.
* **sqlparse**: SQL sorgularının daha okunabilir hâlde formatlanmasını sağlar.
* **tzdata**: Zaman dilimi verilerini içerir, saat bilgilerinin doğru çalışmasını destekler.

---

## 4. Yeni Django Projesi Oluşturmak

Proje dizininde yeni bir proje başlatmak için terminalde aşağıdaki komutu çalıştır:

```bash
django-admin startproject backend
```

Bu komut, `backend` adında bir klasör oluşturur ve içinde Django projesi için gerekli temel dosyaları barındırır.

---

## 5. API Uygulamasını Oluşturmak

Şimdi `backend` klasörüne geçmemiz gerekiyor, bunun için terminalde şu komutu çalıştır:

```bash
cd backend
```

Ardından `backend` dizinindeyken aşağıdaki komutla `api` adında bir uygulama oluşturuyoruz:

```bash
python manage.py startapp api
```

---

# 2. Settings Dosyası

## 1. Bazı Kütüphaneleri Dahil Etmek

`settings.py` dosyasına girerek aşağıdaki kütüphaneleri tanımlamamız gerekiyor:

```python
from datetime import timedelta  # Belirli bir zaman aralığını (örneğin 5 dakika, 7 gün) tanımlamak için kullanılır.
from dotenv import load_dotenv  # .env dosyasındaki çevresel değişkenleri projeye dahil etmek için kullanılır.
import os  # Ortam değişkenlerine erişmek ve dosya işlemleri yapmak için kullanılır.

load_dotenv()  # .env dosyasını yükleyerek içindeki değişkenleri aktif hâle getirir.
```

---

## 2. Django projesinin her yerden gelen istekleri kabul etmesini sağlamak

```python
ALLOWED_HOSTS = ["*"]
```

> ⚠️ Geliştirme sürecinde bu ayar işimizi görür, ancak **güvenlik açısından** canlı sunucuda `"*"` yerine sadece izin verdiğin domainleri yazmalısın (örneğin: `["example.com", "127.0.0.1"]`).

---

## 3. JWT Kimlik Doğrulama ve REST Framework Ayarları

```python
# REST Framework Ayarları
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),  # Kimlik doğrulamada JWT kullanılacak
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],  # API’ye yapılan tüm isteklerde kullanıcı giriş yapmış olmalı
}
```

```python
# Simple JWT Ayarları
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),  # Giriş için verilen token 30 dakika geçerli olacak
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),    # Yenileme token’ı ise 1 gün geçerli kalacak
}
```

## 4. INSTALLED_APPS içinde gerekli tanımlamalar
```python
INSTALLED_APPS = [
    ...

    # aps
    "api",

    # REST API için gerekli frameworkler
    "rest_framework",
    "corsheaders"
]
```

## 5. MIDDLEWARE içindeki tanımlamalar
```python
MIDDLEWARE = [
    ...

    # CORS (farklı origin'lerden gelen isteklere izin vermek için)
    "corsheaders.middleware.CorsMiddleware",
]
```

---

## 6. CORS Ayarları

```python
CORS_ALLOW_ALL_ORIGINS = True  # Geliştirme sırasında tüm sitelerden istek kabul edilir, ama bu güvenlik açısından risklidir.
CORS_ALLOW_CREDENTIALS = True  # Farklı sitelerden çerez ve kimlik bilgisi gönderilmesine izin verir.
```

> Buradaki ayarları sadece geliştirme sürecinde kullan. İş bittiğinde mutlaka değiştir.
> `CORS_ALLOW_ALL_ORIGINS` değerini `False` yapıp, sadece izin verdiğin domainleri şu şekilde belirtmelisin:

```python
CORS_ALLOWED_ORIGINS = [
    "https://example.com",
    "https://www.example.com",
]
```

---

# 3. api/models.py Dosyası: Veritabanı Tablolarını Tanımlama

Verileri veritabanında tutmak için modeller oluşturuyoruz.
Her model, aslında veritabanında bir tabloya karşılık gelir. Örneğin `Note` modeli, başlık, içerik, oluşturulma tarihi ve yazan kullanıcı gibi bilgileri saklar.

```python
from django.db import models
from django.contrib.auth.models import User

class Note(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notes")

    def __str__(self):
        return self.title
```

> Not: Modeli oluşturduktan sonra, değişiklikleri veritabanına yansıtmak için `makemigrations` ve `migrate` komutlarını kullanmalısınız.

Migration dosyasını oluşturmak için:

```bash
python manage.py makemigrations
```

Migrationları veritabanına uygulamak için:

```bash
python manage.py migrate
```

---

# 4. Serializers Dosyasını Hazırlamak

## Serializer Nedir, Neden Kullanırız?

Serializer, modellerimiz ile API arasındaki köprü görevi görür.
Yani, veriyi JSON formatına çevirir ve API’den gelen veriyi doğrulayıp modele uygun hale getirir.

Mesela, `UserSerializer` sayesinde kullanıcı bilgilerini kolayca alıp gönderebiliyoruz.
Parola ise sadece yazılabilir olarak ayarlanır, böylece kimse parolayı okuyamaz.
Ayrıca yeni kullanıcı oluşturmayı da basitleştirir.

Özetle, API ile veri alışverişini problemsiz yapmak için serializer’lar şarttır.

> Serializer dosyasını `api` klasörünün içine `serializers.py` adıyla oluşturuyoruz.

Örnek:

```python
from django.contrib.auth.models import User  # Django'nun hazır User modeli
from rest_framework import serializers       # DRF serializer sınıfları
from .models import Note                      # Kendi modelimiz (örnek)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "password"]
        extra_kwargs = {"password": {"write_only": True}}  # Parola sadece yazılabilir

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)  # Şifreyi hashleyerek kullanıcı oluşturur
        return user

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ["id", "title", "content", "created_at", "author"]
        extra_kwargs = {"author": {"read_only": True}}  # Author sadece okunabilir
```

---

# 5. Views Dosyası (api içinde hazır bulunur)

## Views Dosyası Nedir, Ne İşe Yarar?

Views dosyası, API’mizin nasıl çalışacağını belirlediğimiz yerdir.
Yani, gelen isteklerin karşılandığı, hangi verinin gösterileceği veya kaydedileceğinin kontrol edildiği bölümdür.

### Örnek: `NoteListCreate` Sınıfı

Bu sınıf `ListCreateAPIView`’den türemiştir. Yani hem notları listeleyebiliyor, hem de yeni not ekleyebiliyoruz.

* `serializer_class` ile hangi serializer’ın kullanılacağını belirtiriz; burada `NoteSerializer` seçilmiş.
* `permission_classes` ile ise sadece giriş yapmış kullanıcıların bu işlemleri yapabileceğini belirtiyoruz.

---

### Nasıl Çalışıyor?

* `get_queryset` fonksiyonu, kullanıcının sadece kendi notlarını görmesini sağlar.
* `perform_create` fonksiyonu, yeni not oluşturulurken notun yazarı olarak mevcut kullanıcıyı atar.
* Eğer veri doğrulamada hata varsa, bu hatalar konsola yazdırılır.

---

### Kod Örneği:

```python
from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework import generics
from .serializers import UserSerializer, NoteSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Note

class NoteListCreate(generics.ListCreateAPIView):
    serializer_class = NoteSerializer                # Notlar için serializer belirleniyor
    permission_classes = [IsAuthenticated]           # Sadece giriş yapmış kullanıcılar erişebilir

    def get_queryset(self):
        user = self.request.user                       # Şu anki kullanıcı alınır
        return Note.objects.filter(author=user)       # Kullanıcının kendi notları döner

    def perform_create(self, serializer):
        if serializer.is_valid():                      # Veri doğruysa
            serializer.save(author=self.request.user) # Notun yazarı atanır
        else:
            print(serializer.errors)                   # Hatalar konsola yazılır

class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]
```

---

# 6. Urls Dosyaları

Projede birden fazla `urls.py` dosyası olacak. Her bir uygulamanın (`app`) kendi `urls.py` dosyası olur ama bunların hepsini bir araya toplayan ana bir `urls.py` dosyası da vardır.

Biz yukarıda `api` içindeki view'ları tanımladık, şimdi onları URL'lere bağlamamız lazım. Bu yüzden `api` klasörü içinde yeni bir `urls.py` dosyası oluşturuyoruz.

## api/urls.py

```python
from django.urls import path  # URL tanımlamalarında kullanıyoruz
from . import views          # Views içindeki sınıfları/metodları çağırabilmek için

urlpatterns = [
    path("notes/", views.NoteListCreate.as_view(), name="note-list"),  # Notları listeleyen ve ekleyen endpoint
]
```

---

## Ana Projedeki urls.py Dosyası

Ana `urls.py`, gelen isteklerin (URL’lerin) hangi view’a yönlendirileceğini belirler. Yani API’mizin kapı bekçisi gibi çalışır.

---

### Kodun Detayları

```python
from django.contrib import admin
from django.urls import path, include
from api.views import CreateUserView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),                                    # Django admin paneli
    path('api/user/register/', CreateUserView.as_view(), name="register"),   # Yeni kullanıcı kaydı için endpoint
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # JWT token alma
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # Token yenileme
    path('api-auth/', include('rest_framework.urls')),                 # DRF’nin hazır login/logout sayfaları
    path("api/", include('api.urls')),                                 # api uygulamasındaki URL’leri ekle
]
```

* `admin/`: Django’nun yönetim paneline erişim sağlar.
* `api/user/register/`: Kullanıcı kayıt işlemi için kullanılır.
* `api/token/` ve `api/token/refresh/`: JWT tabanlı kimlik doğrulama için token alma ve yenileme yolları.
* `api-auth/`: Django REST Framework’ün kendi oturum açma-kapama sayfaları.
* `api/`: `api` uygulamasının kendi içindeki URL’leri dahil eder.

---

### Özet

Kısacası, burada uygulamanın farklı işlevlerine ait URL’leri tanımlıyoruz ve gelen istekler doğru view’lara yönlendiriliyor. Böylece API’miz düzgün ve sağlıklı çalışıyor.

---

# 7. Projeyi Çalıştırmak

Projeyi çalıştırmak ve her şeyin yolunda olup olmadığını görmek için terminalde aşağıdaki komutu yazman gerek:

```bash
python manage.py runserver
```

Komutu çalıştırdığında terminalde şu tarz bir çıktı görürsün:

```
Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
May 17, 2025 - 22:03:14
Django version 5.2.1, using settings 'backend.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.

WARNING: This is a development server. Do not use it in a production setting. Use a production WSGI or ASGI server instead.
For more information on production servers see: https://docs.djangoproject.com/en/5.2/howto/deployment/
```

Eğer böyle bir çıktı alırsan, sorun yok demektir. O zaman `http://127.0.0.1:8000/` adresine tarayıcıdan tıklayabilir ya da yapıştırarak projeni açabilirsin.

Projeyi durdurmak istediğinde ise terminalde `Ctrl + C` tuşlarına basman yeterli olacaktır.

---

# Backend Yapısı
```bash
backend:.
│   db.sqlite3
│   manage.py
│   
├───api
│   │   admin.py
│   │   apps.py
│   │   models.py
│   │   serializers.py
│   │   tests.py
│   │   urls.py
│   │   views.py
│   │   __init__.py
│   │
│   ├───migrations
│   │   │   0001_initial.py
│   │   │   __init__.py
│   │   │
│   │   └───__pycache__
│   │           0001_initial.cpython-313.pyc
│   │           0002_note_image.cpython-313.pyc
│   │           0002_uploadedimage.cpython-313.pyc
│   │           __init__.cpython-313.pyc
│   │
│   └───__pycache__
│           admin.cpython-313.pyc
│           apps.cpython-313.pyc
│           models.cpython-313.pyc
│           serializers.cpython-313.pyc
│           urls.cpython-313.pyc
│           views.cpython-313.pyc
│           __init__.cpython-313.pyc
│
└───backend
    │   asgi.py
    │   settings.py
    │   urls.py
    │   wsgi.py
    │   __init__.py
    │
    └───__pycache__
            settings.cpython-313.pyc
            urls.cpython-313.pyc
            wsgi.cpython-313.pyc
            __init__.cpython-313.pyc
```

---

# **🎨 FRONTEND -> React + Vite**

<p align="center">
  <img src="https://github.com/user-attachments/assets/802b0b74-3244-4130-95d3-35e5ec30dd8c" width="30%" />
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="https://github.com/user-attachments/assets/cababf97-2157-4c5c-9885-0337bc69065e" width="30%" />
</p>




## 1. Komutlar

### React Vite Projesi Oluşturmak

Projeyi React ve JavaScript kullanarak oluşturacağız. Bunun için terminalde, `ana klasör` içindeyken şu adımları takip etmen gerekiyor.

Öncelikle, eğer başka bir klasördeysen ana klasöre dönmek için:

```bash
cd ..
```

Sonra React projesini başlatmak için şu komutu çalıştır:

```bash
npm create vite@latest frontend -- --template react
```

Burada, karşına çıkan seçeneklerden `react`’i seçmelisin:

```bash
> npx
> create-vite frontend react

│
◆  Select a framework:
│  ○ Vanilla
│  ○ Vue
│  ● React
│  ○ Preact
│  ○ Lit
│  ○ Svelte
│  ○ Solid
│  ○ Qwik
│  ○ Angular
│  ○ Marko
│  ○ Others
```

Sonra, JavaScript kullanacağımız için bu seçeneği işaretle:

```bash
> npx
> create-vite frontend react

│
◇  Select a variant:
│  ○ TypeScript
│  ○ TypeScript + SWC
│  ● JavaScript
│  ○ JavaScript + SWC
│  ○ React Router v7 ↗
│  ○ TanStack Router ↗
│  ○ RedwoodSDK ↗
```

Seçtikten sonra, `frontend` adında yeni bir klasör oluşacak.

Terminalde ayrıca şöyle bir mesaj görürsün:

```bash
> npx
> create-vite frontend react

│
◇  Select a framework:
│  React
│
◇  Select a variant:
│  JavaScript
│
◇  Scaffolding project in E:\visual studio code projects\dijango\test\frontend...
│
└  Done. Now run:

  cd frontend
  npm install
  npm run dev
```

Bu adımları takip ederek projeni çalıştırabilirsin:

```bash
cd frontend
```

Sonra ihtiyacımız olan paketleri yükleyelim:

```bash
npm install axios react-router-dom jwt-decode
```

Ve projeyi başlat:

```bash
npm run dev
```

Eğer hata görmüyorsan, frontend sunucun başarılı şekilde çalışıyor demektir.

Projeyi durdurmak istediğinde ise terminalde `Ctrl + C` tuşlarına basman yeterlidir.

---

# 2. Gerekli Ekleme ve Temizleme İşlemleri

## 1. Projeden Gereksiz Dosyaları Kaldırmak (src klasörü içinde)

> Her geliştiricinin çalışma tarzı farklıdır, ben kendi alışkanlığıma göre yapıyorum; sen de kendi tarzına göre düzenleyebilirsin.

`frontend/src` klasöründe aşağıdaki dosyaları silebilirsin:

* `src/App.css`
* `src/index.css`

## 2. Projeyi Gereksiz Kodlardan Temizlemek (src klasöründe)

Projeye daha temiz ve sade bir başlangıç yapmak için gereksiz kodları kaldırmamız gerekiyor.

* `App.jsx` dosyasını tamamen boş, sadece temel yapısıyla bırak:

```jsx
import React from "react";

function App() {
  return (
    <>
      {/* Buraya ileride bileşenler gelecek */}
    </>
  );
}

export default App;
```

* `main.jsx` dosyasından ise CSS dosyalarına yapılan importları kaldır:

Örneğin, `main.jsx`’de şöyle bir satır vardı:

```jsx
import './index.css'
```

Bunu kaldırdıktan sonra dosyanın güncel hali şöyle olur:

```jsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

Böylece proje daha sade ve temiz bir hale gelir, yeni kodlar için sağlam bir temel oluşturmuş oluruz. 

---

## 3. Gerekli Klasörler ve Dosyaları Oluşturmak (src klasörü içinde)

Projeyi düzenli ve anlaşılır tutmak için bazı klasörler ve dosyalar ekleyelim.

### Klasörler

* **pages:** Uygulamanın sayfalarını burada tutacağız.
* **styles:** Stil dosyalarını buraya koyacağız.
* **components:** Tekrar kullanılabilir bileşenleri burada oluşturacağız.

### Dosyalar

* **constants.js**
* **api.js**

---

### constants.js İçeriği

```js
export const ACCESS_TOKEN = 'token';
export const REFRESH_TOKEN = 'refresh_token';
```

Bu dosyada, uygulama genelinde kullanacağımız sabit değerleri tanımlıyoruz. Mesela, token’ları localStorage’dan çekerken bu isimlerle erişeceğiz.

---

### api.js İçeriği

```js
import axios from 'axios';
import { ACCESS_TOKEN } from './constants';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL, // API adresini .env dosyasından alacağız
});

// Her isteğe erişim token’ını eklemek için interceptor kullanıyoruz
api.interceptors.request.use(
    (config) => {
        const accessToken = localStorage.getItem(ACCESS_TOKEN); // localStorage’dan token’ı al
        if (accessToken) {
            config.headers.Authorization = `Bearer ${accessToken}`; // İstek header’ına ekle
        }
        return config;
    },
    (error) => {
        return Promise.reject(error); // Hata durumunda reddet
    }
);

export default api;
```

Burada, axios’u kendi özel ayarlarımızla kullanıyoruz. Böylece her API isteğinde otomatik olarak token header’ına ekleniyor. API URL’sini ise `.env` dosyasından okuyacağız, onu da sonraki adımlarda ayarlayacağız.


Bu yapı, projenin ilerleyen aşamalarında kodları daha kolay yönetmemizi ve token ile güvenliği sağlamamızı kolaylaştıracak. 

---

## 4. Proje Klasöründe `.env` Dosyasını Oluşturmak

Frontend projemizin backend’e bağlanabilmesi için, backend’in adresini belirtmemiz gerekiyor. Bunun için frontend klasörünün içinde bir `.env` dosyası oluşturacağız.

Bu dosyanın içinde şu satırı ekleyin:

```env
# Django backend API’nin yerel adresi
VITE_API_URL="http://localhost:8000"
```

Böylece frontend, API isteklerini bu adrese gönderecek. İleride backend adresi değişirse sadece bu dosyayı güncellemek yeterli olacak.

---

## 5. Components Oluşturmak

Projede ihtiyacımız olan bazı bileşenler var. Öncelikle `ProtectedRoute.jsx` bileşenini oluşturacağız. Bu bileşen, sadece giriş yapmış kullanıcıların erişebileceği sayfaları korumak için kullanılır. Daha sonra genellikle projelerde kullanılan `Layout.jsx` veya `Form.jsx` gibi bileşenleri ekleyebiliriz.

---

### components/ProtectedRoute.jsx

```jsx
import { Navigate } from "react-router-dom";
import jwtDecode from "jwt-decode";
import api from "../api";
import { ACCESS_TOKEN, REFRESH_TOKEN } from "../constants";
import { useState, useEffect } from "react";

function ProtectedRoute({ children }) {
  const [isAuthorized, setIsAuthorized] = useState(null);

  useEffect(() => {
    auth().catch(() => setIsAuthorized(false));
  }, []);

  const refresh_token = async () => {
    const refreshToken = localStorage.getItem(REFRESH_TOKEN);

    try {
      const res = await api.post("/api/token/refresh/", { refresh: refreshToken });

      if (res.status === 200) {
        localStorage.setItem(ACCESS_TOKEN, res.data.access);
        setIsAuthorized(true);
      } else {
        setIsAuthorized(false);
      }
    } catch (error) {
      console.error(error);
      setIsAuthorized(false);
    }
  };

  const auth = async () => {
    const token = localStorage.getItem(ACCESS_TOKEN);
    if (!token) {
      setIsAuthorized(false);
      return;
    }

    const decoded = jwtDecode(token);
    const tokenExpiration = decoded.exp;
    const now = Date.now() / 1000;

    if (tokenExpiration < now) {
      await refresh_token();
    } else {
      setIsAuthorized(true);
    }
  };

  if (isAuthorized === null) {
    return <div>Loading...</div>;
  }

  return isAuthorized ? children : <Navigate to="/login" />;
}

export default ProtectedRoute;
```

---

### Açıklama

Bu bileşen, kullanıcıların sadece giriş yapmışlarsa belirli sayfalara erişmesini sağlar. Tarayıcıda geçerli bir access token varsa, sayfa gösterilir. Eğer token süresi dolmuşsa, refresh token ile otomatik olarak token yenileme yapılır. Yenileme başarısız olursa, kullanıcı giriş sayfasına yönlendirilir.

---

## 6. Genel Olarak Her Projede Bulunan Sayfaları Eklemek

Çoğu projede standart olarak `Home`, `Login`, `Register` ve `NotFound` sayfaları olur. Biz de bu sayfaları oluşturarak frontend ile backend arasındaki bağlantıyı kurmak için temel yapıyı hazırlayacağız.

---

### pages/Home.jsx

```jsx
function Home() {
  return <div>Home</div>;
}

export default Home;
```

---

### pages/Login.jsx

```jsx
function Login() {
  return <div>Login</div>;
}

export default Login;
```

---

### pages/Register.jsx

```jsx
function Register() {
  return <div>Register</div>;
}

export default Register;
```

---

### pages/NotFound.jsx

```jsx
function NotFound() {
  return <div>Not Found</div>;
}

export default NotFound;
```

Bu temel sayfalar, projenin iskeletini oluşturacak ve ileride içeriklerini geliştirebileceğimiz ana yapıyı sağlayacak.

---


# 3. App.jsx Dosyasını Güncelleme

Bu dosya, uygulamanın sayfalar arası geçişlerini yönetiyor. Burada şöyle bir mantık kuruyoruz:

* Kullanıcı giriş yapmamışsa sadece **Login** ve **Register** sayfalarına girebilsin.
* Giriş yapan kullanıcılar ise korumalı sayfalara (mesela **Home**) erişebilsin.
* Çıkış yapınca (logout) tarayıcıdaki tüm tokenlar temizlenip kullanıcı otomatik olarak login sayfasına yönlendirilsin.

---

### Güncel App.jsx içeriği şu şekilde olacak:

```jsx
import React from "react"
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import Login from "./pages/Login"
import Register from "./pages/Register"
import Home from "./pages/Home"
import NotFound from "./pages/NotFound"
import ProtectedRoute from "./components/ProtectedRoute"

function Logout() {
  localStorage.clear()
  return <Navigate to="/login" />
}

function RegisterAndLogout() {
  localStorage.clear()
  return <Register />
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route 
          path="/" 
          element={
            <ProtectedRoute>
              <Home />
            </ProtectedRoute>
          } 
        />
        <Route path="/login" element={<Login />} />
        <Route path="/logout" element={<Logout />} />
        <Route path="/register" element={<RegisterAndLogout />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
```


Bu yapı sayesinde, kullanıcı girişi olmadan kritik sayfalara erişimi engellemiş olduk. Ayrıca çıkışta da verileri temizleyip güvenli şekilde login sayfasına yönlendiriyoruz.

---

# 4. Kontrol ve Projeyi Çalıştırma

Öncelikle terminalde **frontend** klasöründeyken şu komutları sırayla çalıştır:

```bash
npm install
```

Bu komut, projenin ihtiyaç duyduğu tüm paketleri yükler.

Ardından:

```bash
npm run dev
```

Bu komutla da projeni çalıştırırsın.

Terminal sana bir link verecek, genellikle şöyle bir adres olur: `http://localhost:3000`

Bu linke tıkladığında ekranda **Home** yazısını görmelisin. Çünkü şu anda `Home.jsx` sayfasındayız.

Şimdi istersen tarayıcının adres çubuğuna `/login`, `/register` gibi adresler yazarak sayfaların düzgün çalışıp çalışmadığını kontrol edebilirsin.

Her şey sorunsuzsa, demek ki frontend kısmı hazır ve yola devam edebiliriz. :)

---

# 5. Form.jsx Bileşenini Oluşturmak

Bu bileşen, hem kullanıcı girişi hem de kayıt işlemleri için ortak bir form yapısı sunuyor. Yani, iki farklı form yazmak yerine, tek bir bileşenle bu işleri hallediyoruz.

Bileşen dışarıdan iki tane bilgi alıyor:

* `route`: Formun verileri göndereceği backend adresi (örneğin, login için `/api/token/`, kayıt için başka bir endpoint).
* `method`: Formun amacını belirtiyor, yani “login” mi yoksa “register” mı olduğu. Bu sayede formun başlığı ve işleyişi buna göre şekilleniyor.

Formda kullanıcı adı ve şifre alanları var. “Gönder” butonuna basıldığında:

* Eğer login işlemi ise, backend’den gelen access ve refresh token’lar localStorage’a kaydediliyor ve kullanıcı ana sayfaya yönlendiriliyor.
* Eğer kayıt işlemi ise, başarılı olursa kullanıcı otomatik olarak login sayfasına yönlendiriliyor.

Ayrıca, form gönderilirken ufak bir “Loading...” göstergesi çıkıyor, böylece kullanıcı işlemin devam ettiğini anlayabiliyor.

---

### Form.jsx kodu

```jsx
import { useState } from "react";
import api from "../api";
import { useNavigate } from "react-router-dom";
import { ACCESS_TOKEN, REFRESH_TOKEN } from "../constants";

function Form({ route, method }) {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const name = method === "login" ? "Login" : "Register";

    const handleSubmit = async (e) => {
        setLoading(true);
        e.preventDefault();

        try {
            const res = await api.post(route, { username, password });
            if (method === "login") {
                localStorage.setItem(ACCESS_TOKEN, res.data.access);
                localStorage.setItem(REFRESH_TOKEN, res.data.refresh);
                navigate("/");
            } else {
                navigate("/login");
            }
        } catch (error) {
            alert(error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="form-container">
            <h1>{name}</h1>
            <input
                className="form-input"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
            />
            <input
                className="form-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
            />
            {loading && <div>Loading...</div>}
            <button className="form-button" type="submit">
                {name}
            </button>
        </form>
    );
}

export default Form;
```


Böylece form bileşenimiz hem login hem de kayıt sayfalarında rahatlıkla kullanılabilir. Sonraki adımda, bu bileşeni login ve register sayfalarına entegre edeceğiz.

---

## 1. Kayıt Sayfasına Form Bileşenini Eklemek

`Register.jsx` dosyamızı şöyle güncelliyoruz:

```jsx
import Form from "../components/Form";

function Register() {
  return <Form route="api/user/register/" method="register" />;
}

export default Register;
```

Burada `Form` bileşenine kayıt işlemi için gerekli `route` ve `method` bilgilerini veriyoruz.

---

## 2. Giriş Sayfasına Form Bileşenini Eklemek

`Login.jsx` dosyamız da benzer şekilde:

```jsx
import Form from "../components/Form";

function Login() {
  return <Form route="api/token/" method="login" />;
}

export default Login;
```

Burada da `Form` bileşenine login için gerekli olan endpoint ve metodu iletiyoruz.

---

## 3. Çalıştırıp Kontrol Etmek

Şimdi terminalde frontend klasöründeyken şu komutla React uygulamamızı başlatıyoruz:

```bash
npm run dev
```

Tarayıcıda giriş ve kayıt sayfalarını açıp form inputlarının düzgün göründüğünden emin olabilirsin. Butona basınca şimdilik backend ile bağlantı olmadığından bir şey olmayacak, bu normal. Ama form görünümü ve temel işleyiş burada hazır.

---

# 6. Frontend ile Backend’i Birleştirmek

İşte beklediğimiz an geldi: Artık frontend’i backend’e bağlayacağız!

Öncelikle backend klasörüne gidip Django sunucumuzu çalıştıralım.

Eğer şu an frontend klasöründeysen, terminalde hızlıca backend klasörüne geçmek için şu komutu kullanabilirsin:

```bash
cd ../backend
```

Backend klasöründeyken Django sunucusunu başlatmak için:

```bash
python manage.py runserver
```

Sunucu başarıyla açılırsa terminalde şöyle bir çıktı görürsün:

```bash
May 17, 2025 - 13:11:49
Django version 5.2.1, using settings 'backend.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.
```

İşte bu adres bizim API’mizin çalıştığı yer. Bu yüzden frontend klasöründeki `.env` dosyamızı şu şekilde güncelliyoruz:

```env
VITE_API_URL="http://127.0.0.1:8000"
```

Şimdi backend terminalini açık bırak, yeni bir terminal aç ve frontend klasörüne dön:

```bash
cd ../frontend
```

React sunucumuzu başlatmak için:

```bash
npm run dev
```

Tarayıcıda açılan adrese tıklayarak sayfamızı görüntüleyebilirsin. Mesela kayıt sayfasına git, yeni bir kullanıcı oluştur. Eğer her şey yolundaysa backend terminalinde şu şekilde bir kayıt log’u göreceksin:

```bash
[17/May/2025 13:35:43] "POST /api/user/register/ HTTP/1.1" 201 29
```

Kayıt olduktan sonra otomatik olarak giriş sayfasına yönlendirileceksin.

Oluşturduğun kullanıcı adı ve şifreyle giriş yap, eğer `Home` sayfasını görebiliyorsan her şey tam anlamıyla çalışıyor demektir. Tebrikler, frontend ile backend arasındaki bağlantıyı kurdun! 🎉

---

# Frontend Yapısı
```bash
frontend:.
│   .env
│   .gitignore
│   eslint.config.js
│   index.html
│   package-lock.json
│   package.json
│   README.md
│   tree.txt
│   vite.config.js
│   
├───node_modules
│   │   .package-lock.json
│   │   
│   └───.bin
│           acorn
│           .
│           .
│           .
│                       
├───public
│       vite.svg
│       
└───src
    │   api.js
    │   App.jsx
    │   constants.js
    │   main.jsx
    │   
    ├───assets
    │       react.svg
    │       
    ├───components
    │       Form.jsx
    │       ProtectedRoute.jsx
    │       UpdaloadImage.jsx
    │       
    ├───pages
    │       Home.jsx
    │       Login.jsx
    │       NotFound.jsx
    │       Register.jsx
    │       
    └───styles
```

---
