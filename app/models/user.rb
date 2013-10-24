class User < ActiveRecord::Base
include BCrypt
	attr_accessible :email, :password, :password_confirmation
	attr_accessor :password
	before_save :encrypt_password , :add_binnary_code

	validates_confirmation_of :password , :message => "Passwords donot match."
	validates_presence_of :password, :message => "Please Enter a Password"
	validates_presence_of :email,:message=>"Email ID Field cannot be blank"
	validates_uniqueness_of :email,:message => "Sorry this Email ID is already registered."

 	def generate_unique_id(len)
		chars = ("0".."9").to_a
		generate_unique_id = ""
		1.upto(len) {  |i| generate_unique_id << chars[rand(chars.size-1)] }
		return generate_unique_id
	end
		
	def chk_binnary_code(binnary_code)
		temp = User.find_by_binnary_code(binnary_code)
		if temp.nil?
			return true
		end
		return false	
	end

  	def self.authenticate(email, password)
    		user = find_by_email(email)
    		if user && user.password_hash == BCrypt::Engine.hash_secret(password, user.password_salt)
      			user
    		else
      			nil
    		end
 	 end

	def encrypt_password
		if password.present?
			self.password_salt = BCrypt::Engine.generate_salt
			self.password_hash = BCrypt::Engine.hash_secret(password, password_salt)
			self.binnary_code = generate_unique_id(9)
		end
	end
	def add_binnary_code
		self.binnary_code = ""
		while true
			binnary_code = generate_unique_id(9)
			chk = chk_binnary_code(binnary_code)
			if chk
				self.binnary_code = binnary_code
				return self.binnary_code
			end	
		end
	end
end
