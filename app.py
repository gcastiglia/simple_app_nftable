from flask import Flask, render_template, request, redirect, url_for,g
from info_system import get_network_interfaces, get_input_rule, get_forward_rule, get_wan_rule, configure_input, delete_nft_rule, get_blacklist, add_bl, del_bl,add_wan,configure_routing,init_fw


app = Flask(__name__)

# Page d'accueil
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/init_firewall')
def init_firewall():
    init_fw()
    return redirect(url_for('interfaces'))

# Page interfaces
@app.route('/interfaces')
def interfaces():
    interfaces_list = get_network_interfaces()
    return render_template('interfaces.html', interfaces=interfaces_list)


@app.route('/rule_to_intern')
def rule_to_intern():
    rules_to_intern_list = get_input_rule()
    return render_template('rules_to_intern.html', rule_to_intern=rules_to_intern_list)

# Pour ajouter une regle interne

@app.route('/add_interface_form')
def add_interface_form():
    return render_template('add_interfaces_form.html')


@app.route('/add_rule_to_intern', methods=['POST'])
def add_rule_to_intern():
    protocol = request.form.get('protocol')
    ip = request.form.get('ip')
    port = request.form.get('port')
    _ = configure_input(ip,protocol,port)
    print(f"regle interne ajouté : {protocol} - {ip} - {port}")
    return """
    <html>
        <body>
            <script>
                window.close();
            </script>
        </body>
    </html>
    """



@app.route('/blacklist')
def blacklist():
    blacklist_list = get_blacklist()
    print(blacklist_list)
    return render_template('blacklist.html', blacklist=blacklist_list)

@app.route('/blacklist_form')
def blacklist_form():
    return render_template('blacklist_form.html')


@app.route('/delete_blacklist/<int:num>', methods=['POST'])
def delete_blacklist(num):
    del_bl(num)
    print(f"ip {num} supprimée de la blacklist")
    return redirect(url_for('blacklist'))


@app.route('/add_ip_to_blacklist', methods=['POST'])
def add_ip_to_blacklist():
    ip = request.form.get('ip')
    add_bl(ip)
    print(f"IP ajouté a la blacklist :  {ip} ")
    return """
    <html>
        <body>
            <script>
                window.close();
            </script>
        </body>
    </html>
    """


@app.route('/delete_input_rule/<int:handle>', methods=['POST'])
def delete_rule(handle):
    etat = delete_nft_rule(handle,"input")
    print(f"Règle {handle} supprimée")
    return redirect(url_for('rule_to_intern'))




@app.route('/rules_to_wan')
def rules_to_wan():
    to_wan_list = get_wan_rule()
    #print(to_wan_list)
    return render_template('rules_to_wan.html', to_wan=to_wan_list)


@app.route('/to_wan_form')
def to_wan_form():
    return render_template('to_wan_form.html')


@app.route('/add_ip_to_wan', methods=['POST'])
def add_ip_to_wan():
    ip = request.form.get('ip')
    add_wan(ip)
    print(f"IP ayant accès à l'internet :  {ip} ")
    return """
    <html>
        <body>
            <script>
                window.close();
            </script>
        </body>
    </html>
    """


@app.route('/delete_wan_rule/<int:handle>', methods=['POST'])
def delete_wan_rule(handle):
    etat = delete_nft_rule(handle,"forward")
    print(f"Règle {handle} supprimée")
    return redirect(url_for('rules_to_wan'))



@app.route('/rules_to_routing')
def rules_to_routing():
    routing_list = get_forward_rule()
    #print(routing_list)
    return render_template('rules_to_routing.html', routing_list=routing_list)


@app.route('/add_routing_form')
def add_routing_form():
    return render_template('add_routing_form.html')


@app.route('/add_routing_rule', methods=['POST'])
def add_routing_rule():
    ip_source = request.form.get('ip_source')
    ip_dest = request.form.get('ip_dest')
    protocol = request.form.get('protocol')
    port = request.form.get('port')
    if(protocol == "ping"):
        port = -1
    configure_routing(ip_source,ip_dest,protocol,port)    
    print(f"IP ayant accès à l'internet :  {protocol} - {port} ")
    return """
    <html>
        <body>
            <script>
                window.close();
            </script>
        </body>
    </html>
    """

@app.route('/delete_routing_rule/<int:handle>', methods=['POST'])
def delete_routing_rule(handle):
    etat = delete_nft_rule(handle,"forward")
    print(f"Règle {handle} supprimée")
    return redirect(url_for('rules_to_routing'))




if __name__ == '__main__':
    app.run(debug=True)
