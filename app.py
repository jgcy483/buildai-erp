from flask import Flask,render_template
app=Flask(__name__)
cards={"income":0,"expense":0,"profit":0}
@app.route("/")
def home():
    return render_template("dashboard.html",cards=cards)
if __name__=="__main__":
    app.run()
