import Fs.Nsp
import Fs.Nca
import Fs.Ticket
import Fs.Cnmt
import Fs.File

def factory(name):
	if name.endswith('.nsp'):
		f = Fs.Nsp.Nsp()
	elif name.endswith('.nsz'):
		f = Fs.Nsp.Nsp()
	elif name.endswith('.nsx'):
		f = Fs.Nsp.Nsp()
	elif name.endswith('.nca'):
		f =  Fs.Nca.Nca()
	elif name.endswith('.tik'):
		f =  Fs.Ticket.Ticket()
	elif name.endswith('.cnmt'):
		f =  Fs.Cnmt.Cnmt()
	else:
		f = Fs.File.File()

	return f