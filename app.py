from flask import Flask

app = Flask(__name__)

@app.route('/')
def add():
    return render_template('add.html')

if __name__ == '__main__':
    app.run(debug=True)