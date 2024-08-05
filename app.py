from flask import Flask, render_template

def create_app():
    app = Flask(__name__)

    @app.route('/')
    def home():
        return render_template('index.html')
      
    @app.route('/about')
    def about():
      return render_template('about.html')
    
    @app.route('/service')
    def service():
      return render_template('service.html')
    
    @app.route('/menu')
    def menu():
      return render_template('menu.html')
    
    @app.route('/booking')
    def booking():
      return render_template('booking.html')
    
    @app.route('/ourteam')
    def ourteam():
      return render_template('ourteam.html')
    
    @app.route('/testimonial')
    def testimonial():
      return render_template('testimonial.html')
    
    @app.route('/contact')
    def contact():
      return render_template('contact.html')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
 