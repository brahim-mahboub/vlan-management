from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from time import strftime
from datetime import datetime
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/Vlans.db'
app.config['SECRET_KEY'] = 'app'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=True)
    lastname = db.Column(db.String(50), nullable=True)
    mail = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50), nullable=True)
    admin = db.Column(db.String(50), nullable=True)


class Infoblox(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status_infoblox = db.Column(db.String(50), nullable=True)
    status_firewall = db.Column(db.String(50), nullable=True)
    status_network = db.Column(db.String(50), nullable=True)
    status_esx = db.Column(db.String(50), nullable=True)
    status_dhcp = db.Column(db.String(50), nullable=True)
    comment = db.Column(db.String(50), nullable=True)
    ot = db.Column(db.String(50), nullable=True)
    it = db.Column(db.String(50), nullable=True)
    ticket_infoblox = db.Column(db.String(50), nullable=True)
    ticket_firewall = db.Column(db.String(50), nullable=True)
    ticket_network = db.Column(db.String(50), nullable=True)
    ticket_esx = db.Column(db.String(50), nullable=True)
    ticket_dhcp = db.Column(db.String(50), nullable=True)
    updated_date = db.Column(db.String(50), nullable=True)
    admin = db.Column(db.String(50), nullable=True)
    VLAN = db.relationship('VLAN', backref='infoblox', uselist=False)


class Network(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(50), nullable=True)
    subnet = db.Column(db.String(50), nullable=True)
    mask = db.Column(db.String(50), nullable=True)
    hosts = db.Column(db.String(50), nullable=True)
    range = db.Column(db.String(50), nullable=True)
    gateway = db.Column(db.String(50), nullable=True)
    VLAN = db.relationship('VLAN', backref='network', uselist=False)


class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(200), nullable=True)
    name = db.Column(db.String(200), nullable=True)


class VLAN(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_network = db.Column(db.Integer, db.ForeignKey('network.id'))
    id_infoblox = db.Column(db.Integer, db.ForeignKey('infoblox.id'))
    id_request = db.Column(db.Integer, db.ForeignKey('request.id'))


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_vlan = db.Column(db.Integer, db.ForeignKey('VLAN.id'))
    hostname = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    subnet_mask = db.Column(db.String(50), nullable=True)
    gateway_ip = db.Column(db.String(50), nullable=True)
    fqdn = db.Column(db.String(50), nullable=True)
    function = db.Column(db.String(50), nullable=True)
    location = db.Column(db.String(50), nullable=True)
    environment = db.Column(db.String(50), nullable=True)
    type = db.Column(db.String(50), nullable=True)
    os = db.Column(db.String(50), nullable=True)


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('user.id'))
    id_site = db.Column(db.Integer, db.ForeignKey('site.id'))
    hosts = db.Column(db.Integer, nullable=True)
    description = db.Column(db.String(50), nullable=True)
    content = db.Column(db.String(50), nullable=True)
    firewall = db.Column(db.String(50), nullable=True)
    esx = db.Column(db.String(50), nullable=True)
    dhcp = db.Column(db.String(50), nullable=True)
    mode = db.Column(db.String(50), nullable=True)
    created_date = db.Column(db.String(50), nullable=True)
    requested_date = db.Column(db.String(50), nullable=True)
    VLAN = db.relationship('VLAN', backref='request', uselist=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logmein', methods=['POST', 'GET'])
def logmein():
    if request.method == "POST":
        userMail = request.form['mail']
        userPassword = request.form['password']
        user = User.query.filter_by(mail=userMail).first()
        admin = user.admin

        if bcrypt.checkpw(userPassword.encode('utf-8'), user.password):
                login_user(user)
                if admin == "True":
                    return render_template('/admin/dashboard.html', g=user)
                else :
                    return redirect('/siteClient')
        else:
                return 'Mauvais mot de passe'

@app.route('/login',methods=['POST','GET'])
def login():
	return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('/visitor/home.html')



@app.route('/registration', methods=['POST', 'GET'])
def inscription():
    if request.method == "POST":
        userFirstname = request.form['firstname']
        userLastname = request.form['lastname']
        userMail = request.form['mail']
        userPasswword = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())

        new_User = User(firstname=userFirstname, lastname=userLastname, mail=userMail,
                        password=userPasswword, admin="False")

        db.session.add(new_User)
        db.session.commit()
        return render_template('/visitor/connection.html')

    else:

        return render_template('/visitor/registration.html')

@app.route('/recrutement', methods=['POST', 'GET'])
def recruter():
    if request.method == "POST":
        userFirstname = request.form['firstname']
        userLastname = request.form['lastname']
        userMail = request.form['mail']
        userPasswword = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())

        new_User = User(firstname=userFirstname, lastname=userLastname, mail=userMail,
                        password=userPasswword, admin="True")

        db.session.add(new_User)
        db.session.commit()
        return render_template('/admin/dashboard.html')

    else:

        return render_template('/visitor/registration.html')

@app.route('/add_device', methods=['POST', 'GET'])
def addDevice():
    if request.method == "POST":
        vlan = request.form['vlans']
        hostname = request.form['hostname']
        ip = request.form['ip']
        mask = request.form['mask']
        gateway = request.form['gateway']
        fqdn = request.form['fqdn']
        function = request.form['function']
        location = request.form['location']
        env = request.form['env']
        type = request.form['type']
        os = request.form['os']

        new_Device = Device(id_vlan=vlan,hostname=hostname,ip_address=ip,subnet_mask=mask,gateway_ip=gateway,fqdn=fqdn,
							function=function,location=location,environment=env,type=type,os=os)

        db.session.add(new_Device)
        db.session.commit()
        return render_template('/admin/dashboard.html')

    else:

        return redirect('/ext1')

@app.route('/add_network', methods=['POST', 'GET'])
def addNetwork():
    if request.method == "POST":
        state = request.form['state']
        subnet = request.form['subnet']
        mask = request.form['mask']
        hosts = request.form['hosts']
        range = request.form['range']
        gateway = request.form['gateway']

        new_Network = Network(state=state,subnet=subnet,mask=mask,hosts=hosts,range=range,gateway=gateway)

        db.session.add(new_Network)
        db.session.commit()
        return render_template('/admin/dashboard.html')

    else:

        return redirect('/ext2')

@app.route('/add_site', methods=['POST', 'GET'])
def addSite():
    if request.method == "POST":
        name = request.form['name']
        city = request.form['city']

        new_Site = Site(city=city, name=name)

        db.session.add(new_Site)
        db.session.commit()
        return render_template('/admin/dashboard.html')

    else:

        return redirect('/ext3')

@app.route('/add_vlan', methods=['POST', 'GET'])
def addVlan():
    if request.method == "POST":
        vlan = request.form['vlan']
        subnet = request.form['subnets']

        network = Network.query.filter_by(subnet=subnet).first()
        new_VLAN = VLAN(id=vlan, id_network=network.id)
        networkChoosen = Network.query.get_or_404(network.id)
        networkChoosen.state = 'Reserved'
        db.session.add(new_VLAN)
        db.session.commit()
        return render_template('/admin/dashboard.html')

    else:

        return redirect('/ext4')



@app.route('/add_request',methods=['POST','GET'])
def add_request():
    if request.method=="POST":
            id_vlan=request.form['vlanId']
            id_site=request.form['sites']
            hosts = request.form['hosts']
            description=request.form['description']
            content=request.form['content']
            firewall = request.form['firewall']
            dhcp = request.form['dhcp']
            esx=request.form['esx']
            mode=request.form['mode']
            requested=request.form['request_date']
            request1=Request(id_site=id_site,id_user=current_user.id,hosts=hosts,description=description,content=content,
                             firewall=firewall,dhcp=dhcp,esx=esx,mode=mode,created_date=str(datetime.now()),requested_date=str(requested))

            status_infoblox = "To do"

            if firewall=="oui":
                status_firewall= "To do"
            else:
                status_firewall= "Not required"

            status_network = "To do"

            if esx == "oui":
                status_esx = "To do"
            else:
                status_esx = "Not required"

            if dhcp == "oui":
                status_dhcp= "To do"
            else:
                status_dhcp= "Not required"

            if mode == "Lift&Shift":
                it = "To do"
                ot = "None"
            else:
                ot = "To do"
                it = "None"

            infoblox=Infoblox(status_infoblox=status_infoblox,status_firewall=status_firewall,status_dhcp=status_dhcp,
                              status_esx=status_esx,status_network=status_network,comment=content,it=it,ot=ot,
                              updated_date="Not updated",admin="None")

            network_id=Network.query.filter_by(hosts=request.form['hosts'],state="Spare").first()

            network_id.state="Reserved"

            db.session.add(infoblox)
            db.session.add(request1)
            db.session.commit()
            vlan=VLAN(id=id_vlan,id_infoblox=infoblox.id,id_network=network_id.id,id_request=request1.id)
            db.session.add(vlan)
            db.session.commit()

            return redirect('/orders')

    else:
        sites = Site.query.order_by(Site.id)
        networks = Network.query.order_by(Network.id)
        return render_template('/client/order.html', sites=sites, networks=networks)







@app.route('/siteAdmin', methods=['POST', 'GET'])
def siteA():
    sites = Site.query.order_by(Site.id)
    return render_template('/admin/site.html', sites=sites)

@app.route('/siteClient', methods=['POST', 'GET'])
def siteC():
    sites = db.session.query(Request, Site).join(Request).filter(Request.id_user == current_user.id).all()
    return render_template('/client/site.html', sites=sites)

@app.route('/vlanAdmin', methods=['POST', 'GET'])
def vlanA():
    vlans = VLAN.query.order_by(VLAN.id)
    return render_template('/admin/vlan.html', vlans=vlans)

@app.route('/vlanClient', methods=['POST', 'GET'])
def vlanC():
    vlans = db.session.query(Request, VLAN).join(Request).filter(Request.id_user==current_user.id).all()
    return render_template('/client/vlan.html', vlans=vlans)

@app.route('/mydevice', methods=['POST', 'GET'])
def mydevice():
    if request.method == "POST":
        vlans = request.form['vlans']
        results=db.session.query(Request,VLAN,Device). \
            select_from(Request).join(VLAN).join(Device).filter(Request.id_user==current_user.id, VLAN.id== vlans).all()

        return render_template('/client/mydevice.html', devices=results,vlan=vlans)

    else:
        return redirect('/vlanClient')

@app.route('/device', methods=['POST', 'GET'])
def devices():
    if request.method == "POST":
        vlans = request.form['vlans']
        results=Device.query.order_by(Device.id)

        return render_template('/admin/device.html', devices=results,vlan=vlans)

    else:
        return redirect('/vlanAdmin')

@app.route('/myvlans', methods=['POST', 'GET'])
def myvlans():
    if request.method == "POST":
        site = request.form['sites']

        results=db.session.query(Request,VLAN,Network). \
            select_from(Request).join(VLAN).join(Network).filter(Request.id_site == site, Request.id_user==current_user.id).all()
        return render_template('/client/myvlans.html', vlans=results, site=site)


@app.route('/vlans', methods=['POST', 'GET'])
def vlans():
    if request.method == "POST":
        site = request.form['sites']
        results = db.session.query(Request, VLAN, Network). \
            select_from(Request).join(VLAN).join(Network).filter(Request.id_site == site).all()

        return render_template('/admin/vlans.html', vlans=results, site=site)


@app.route('/orders', methods=['POST', 'GET'])
def orders():
        results=db.session.query(Request,Site).join(Request).filter(Request.id_user==current_user.id).all()

        return render_template('/client/myorders.html', datas=results)


@app.route('/myinfoblox', methods=['POST', 'GET'])
def myinfoblox():
    print("Je suis dans myinfoblox")
    results = db.session.query(Infoblox, VLAN, Request). \
        select_from(Infoblox).join(VLAN).join(Request).filter(Request.id_user == current_user.id).all()
    return render_template('/client/myinfoblox.html', results=results)


@app.route('/infoblox', methods=['POST', 'GET'])
def infoblox():

    results = db.session.query(Infoblox, VLAN).join(VLAN).all()

    return render_template('/admin/infoblox.html', results=results)

@app.route('/networks', methods=['POST', 'GET'])
def networks():

    networks = Network.query.order_by(Network.id)

    return render_template('/admin/networks.html', networks=networks)






@app.route('/update_infoblox/<int:id_infoblox>', methods=['POST', 'GET'])
def update_infoblox(id_infoblox):
	infoblox_to_update = Infoblox.query.get_or_404(id_infoblox)
	vlan=VLAN.query.filter_by(id_infoblox=id_infoblox).first()
	if request.method == "POST":

		try:
			infoblox_to_update.status_infoblox=request.form['infoblox']
			infoblox_to_update.status_firewall = request.form['firewall']
			infoblox_to_update.status_network = request.form['network']
			infoblox_to_update.status_esx = request.form['esx']
			infoblox_to_update.status_dhcp = request.form['dhcp']
			infoblox_to_update.comment = request.form['comment']

			db.session.commit()
			return render_template('admin/infoblox.html', id_vlan=vlan.id, infoblox=infoblox_to_update)
		except:
			return "erreur"
	else:
		return render_template('/admin/update_infoblox.html', infoblox=infoblox_to_update, id_vlan=vlan.id)


@app.route('/update_machine/<Host_Name>', methods=['POST', 'GET'])
def update_machine(Host_Name):
	machine_to_update = Device.query.get_or_404(Host_Name)
	if request.method == "POST":
		machine_to_update.Host_Name = request.form['host']
		machine_to_update.IP_Address = request.form['ip']
		machine_to_update.VLAN_ID = request.form['vlan']
		try:
			db.session.commit()
			return redirect('/machine')
		except:
			return "erreur"
	else:
		return render_template('/admin/update_machine.html', machine_to_update=machine_to_update)


@app.route('/update_vlan/<int:VLAN_ID>', methods=['POST', 'GET'])
def update_vlan(VLAN_ID):
	vlan_to_update = VLAN.query.get_or_404(VLAN_ID)
	network = Network.query.filter_by(state="Reserved").all()
	if request.method == "POST":
		if(vlan_to_update.id_network==None):
			vlan_to_update.id_network = request.form['subnet']
			network_to_update2 = Network.query.get_or_404(request.form['subnet'])
			network_to_update2.state="Reserved"
		else:
			network_to_update = Network.query.get_or_404(vlan_to_update.id_network)
			vlan_to_update.id_network = request.form['subnet']
			network_to_update2 = Network.query.get_or_404(request.form['subnet'])
			network_to_update2.state="Reserved"
			network_to_update.state="Spare"
		try:
			db.session.commit()
			request1 = Request.query.filter_by(id=vlan_to_update.id_request).first()
			results = db.session.query(Request, VLAN, Network).join(Request).outerjoin(Network). \
				filter(Request.id_site ==request1.id_site ).all()
			return render_template('/admin/vlans.html', Vlans=results, site=request1.id_site)
		except:
			return "erreur"
	else:

		return render_template('/admin/update_vlan.html', id_vlan=VLAN_ID, network=network)


@app.route('/')
def index():
    return render_template('/visitor/home.html')

@app.route('/registration.html')
def registration():
    users = User.query.order_by(User.id)
    return render_template('/visitor/registration.html', users=users)

@app.route('/connection.html')
def connection():
    return render_template('/visitor/connection.html')

@app.route('/dashboard.html')
def dashboard():
	user= current_user
	return render_template('/admin/dashboard.html', g=user)

@app.route('/recrutement.html')
def recrutement():
    return render_template('/admin/recrutement.html')

@app.route('/ext1')
def ext1():
    vlans = VLAN.query.order_by(VLAN.id)
    return render_template('/admin/adddevice.html',vlans=vlans)

@app.route('/ext2')
def ext2():
    return render_template('/admin/addnetwork.html')

@app.route('/ext3')
def ext3():
    return render_template('/admin/addsite.html')

@app.route('/ext4')
def ext4():
    networks = Network.query.order_by(Network.id)
    return render_template('/admin/addvlan.html', networks=networks)

@app.route('/ext5')
def ext5():
    vlans = VLAN.query.order_by(VLAN.id)
    return render_template('/admin/addinfoblox.html', vlans=vlans)

@app.route('/order')
def order():
    sites = Site.query.order_by(Site.id)
    networks = Network.query.order_by(Network.id)

    return render_template('/client/order.html',networks=networks,sites=sites)

if __name__ == '__main__':
    app.run(debug=True)




