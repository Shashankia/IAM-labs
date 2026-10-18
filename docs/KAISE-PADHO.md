# Kaise padhna hai

Yeh lab software engineer banne ke liye nahi hai. IAM engineer screen, log, aur order dekhta hai. Code tab kholna jab koi pooche "yeh step kahan hota hai". Usse pehle mat padhna.

Password har account ka: `Helios#2027`

Ek hi browser use karna. Dusra banda banne se pehle **Log out everywhere** dabana. Warna identity provider purane session se wapas usi aadmi ko sign in kara dega.

## Pehle yeh teen systems alag pehchaan lo

| Jo dikhe | Woh kya hai |
|---|---|
| Neela page, Helios Identity | Identity provider. Password yahin jaata hai. Admin console bhi yahin hai. |
| Garam / paper colour, Leave Portal | Company ki app. Iske paas password store nahi hota. |
| Green colour, Payroll | Doosri app. Iske accounts SCIM se aate hain, HR sheet se seedha nahi. |

Jab browser neele page par jump kare, samajh lena: app ne tumhe identity provider ke paas bhej diya.

## 25 minute ka order

1. http://127.0.0.1:8080 kholo. `iam.admin` se sign in karo. Applications, Users, aur Sign-in log dekho. Yahi job ka console hai.
2. Leave Portal kholo. `aisha.khan` se sign in karo. Home par token versus directory wali table dekho. Phir **Your token** kholo. Table padho. Neeche ka signature tab tak mat kholna jab tak table samajh na aa jaye.
3. Usi browser mein Payroll kholo. Neela page aayega: "Already signed in". Password nahi maangega. Continue dabao. Yahi single sign-on hai.
4. Leave Portal par **Team Wiki (SAML)** kholo. Assertion ki table padho. NameID, audience, expiry. XML baad mein.
5. **Log out everywhere.** Phir `neha.joshi` se sign in karo. Password ke baad 6 digit code aayega. Page par jo code likha hai wohi daalo. Yahi MFA hai.
6. HR feed par order yeh rakho: Hire Meera, Transfer Aisha to Finance, Exit Vikram. Teen columns dekho: HR, Directory, Payroll.
7. Wapas `iam.admin` se console kholo. Vikram disabled dikhe, delete nahi. Aisha ka group Finance ho. Sign-in log mein `leaver` aur `mover` dikhein.
8. `rahul.mehta` se Approvals kholo. Wednesday clock par Aisha allow. Sunday clock par deny.
9. `sara.fernandes` se Vikram allow, Aisha deny. Department match nahi karta.
10. Normal window mein `kabir.das` se prod-admin maango. Private window mein `neha.joshi` se approve karo. Kabir ki window refresh karo. Token purana rahega, directory mein role naya hoga. Do minute ruko. Role gayab ho jayega.

## Har project ke paanch sawal

Inke jawab diagram aur screen se aane chahiye, code se nahi.

**SSO**

1. Password kis system ne dekha?
2. Token kis app ke liye bana? (`aud`)
3. Token kisne banaya? (`iss`)
4. Doosri app ne password kyun nahi maanga?
5. Token expire hone ke baad kya karna padta hai?

**Joiner mover leaver**

1. Hire ke baad login kahan banta hai?
2. Transfer par group badalta hai ya role?
3. Exit par account delete hota hai ya disable?
4. Purana token exit ke baad turant mar jaata hai?
5. Console par disable karne ke baad reconcile kyun wapas enable kar sakta hai?

**Authorization**

1. Manager hone se hi approval kyun nahi milti?
2. Rahul Aisha ko kyun approve kar sakta hai, Vikram ko nahi?
3. Sunday clock deny kyun karta hai?
4. Policy file mein kaun si teen conditions hain?
5. Policy allow ho tab bhi token mein role badla, ya nahi?

**Privileged access**

1. Shuruat mein prod-admin kiske paas hai?
2. Approve ke baad token mein role kyun nahi dikhta?
3. Do minute baad role kaun hatata hai?
4. Certify aur revoke mein farq kya hai?
5. Log mein approver ka naam kahan hai?

## Code kab kholna hai

Sirf teen files, aur sirf tab:

| File | Kab |
|---|---|
| `helios/jml.py` | Jab koi pooche joiner ke steps kya hain. Upar ka comment hi padhna. |
| `policies/leave.rego` | Jab approval deny ho chuki ho aur tum woh char lines dekhna chahte ho. |
| `helios/oidc_client.py` | Jab koi pooche app sign-in par kya karti hai. Upar ke paanch steps. |

`store.py`, HTML, aur CSS mat padhna. Woh filing cabinet aur paint hain.

## Interview mein kaise bolna hai

"Maine ek lab company chalayi. Employee app ko OIDC code flow aur PKCE se sign in karaya. Doosri app ne wahi identity session use kiya, password doosri baar nahi gaya. HR event par worker ne directory mein account banaya, group lagaya, aur Payroll ko SCIM se push kiya. Exit par account disable hua, delete nahi. Approval ek policy se hui: manager, same department, business hours. Production admin do minute ke liye mila aur worker ne hata diya. Token ek snapshot tha. Directory badalne par purana token khud update nahi hua."

Yeh paragraph yaad kar lena. Details screens se aayengi.
