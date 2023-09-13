from flask import Flask
from datetime import datetime
from flask import render_template, request, url_for, redirect, session
from app.my_forms import HostPortForm
import scan
from scapy.all import ICMP, IP, sr1, TCP

# Eine globale Variable zum Speichern der Formulardaten
#form_data = {}

app = Flask(__name__)
app.secret_key = 'your_secret_key'
my_list = []
test = None
startwert = "Ergebniss"

@app.route('/')
def index():
    jetzt = datetime.now()
    current_datetime = jetzt.strftime("%H:%M %d.%m.%Y")
    startwert = "in der Eingabe bitte die IP eingeben und den Portbereich z.B. so 80-90"
    return render_template('start.html', startwert=startwert, current_datetime=current_datetime)


@app.route('/input', methods=['GET', 'POST'])
def input():
    form = HostPortForm()
    if form.validate_on_submit():
        host = form.host.data
        portrange = form.portrange.data
        fhost = {host}
        fportrange = {portrange}

        input_string = str(fportrange)
        fportrange = input_string.strip('{}').replace("'", '')

        input_string = str(fhost)
        fhost = input_string.strip('{}').replace("'", '')
        my_list.clear()
        #my_list.append(scan.finalscan(fhost,fportrange))
        scan.finalscan(fhost, fportrange, my_list)

        print(my_list)








        # Weiterleitung an die Ergebnisse-Seite
        return redirect(url_for('ergebnis'))
    return render_template('input.html', form=form)

@app.route('/ergebnis')
def ergebnis():
    return render_template('ergebnis.html', startwert=startwert, my_list=my_list)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
