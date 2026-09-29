# simple_app_nftable

Une application Flask pour gérer grossièremment nftable avec le même fonctionnement globalement que ce projet [prot_cli.py](https://github.com/gcastiglia/cli_nftable/tree/main), il y'a donc les mêmes choix arbitraire pour l'interface NAT et la blacklist

Il faut flask et le paquet nftables de Python

Pour lancer le serveur
```
flask --app app run --host=10.10.60.3 --port=5000 --debugger
```

Puis `initialiser le firewall`


## L'app

L'application tourne sur le serveur de flask, ce qui n'est pas production-ready, mais cela m'as permis de faire un peu de Flask, de plus l'application doit tourner via l'user root

### Accueil 
<img width="1871" height="367" alt="page_accueil" src="https://github.com/user-attachments/assets/48d8d7b6-38ba-44d6-8121-8d84aea33dea" />

### Interface
<img width="1880" height="321" alt="interface" src="https://github.com/user-attachments/assets/29c2cb98-b8fa-4a19-a0ee-d3a9d025d9e7" />

### Regle input 
<img width="1879" height="706" alt="input" src="https://github.com/user-attachments/assets/5c1c5882-c805-4745-90ad-0d27e61717fa" />

### Blacklist
<img width="1861" height="357" alt="bl" src="https://github.com/user-attachments/assets/7d7616cb-7331-40f2-b041-74a404e02902" />

### To Wan
<img width="1891" height="323" alt="to_wan" src="https://github.com/user-attachments/assets/7273d6cc-5bf9-4beb-a746-95dd754fa0ee" />

### Routing

<img width="1920" height="490" alt="routing" src="https://github.com/user-attachments/assets/4ac9cd38-6039-43ec-9f59-e1cc71a2e921" />

