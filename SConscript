import nil.directory, sys, os

executable = 'syringe'
boost = ARGUMENTS.get('boost')
ail = ARGUMENTS.get('ail')

dependencies = [boost, ail]

if len(filter(lambda x: x == None, dependencies)) > 0:
	print 'This executable requires boost (http://www.boost.org/) and ail (http://repo.or.cz/w/ail.git) so you will have to specify the paths in the scons arguments:'
	print 'scons boost=<boost directory> ail=<ail directory>'
	sys.exit(1)

flags = [
	'/EHsc'
]

relative_source_directory = os.path.join('..', executable)

source_files = map(lambda path: os.path.basename(path), nil.directory.get_files_by_extension(relative_source_directory, 'cpp'))

include_directories = ['.'] + dependencies

cpus = int(os.environ.get('NUMBER_OF_PROCESSORS', 2))

thread_string = 'thread'
if cpus > 1:
	thread_string += 's'
print 'Compiling project with %d %s' % (cpus, thread_string)

environment = Environment(CPPPATH = include_directories, CCFLAGS = flags)
environment.SetOption('num_jobs', cpus)
environment.Program(executable, source_files)