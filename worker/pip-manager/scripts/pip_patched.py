import sys
import pip
from pip.basecommand import RequirementCommand

class ResolveCommand(RequirementCommand):

    name = 'resolve'
    summary = 'Resolve actual version'

    def __init__(self, *args, **kw):
        from pip import cmdoptions

        super(ResolveCommand, self).__init__(*args, **kw)

        cmd_opts = self.cmd_opts

        cmd_opts.add_option(cmdoptions.constraints())
        cmd_opts.add_option(cmdoptions.editable())
        cmd_opts.add_option(cmdoptions.requirements())
        cmd_opts.add_option(cmdoptions.build_dir())
        cmd_opts.add_option(cmdoptions.no_deps())
        cmd_opts.add_option(cmdoptions.global_options())
        cmd_opts.add_option(cmdoptions.no_binary())
        cmd_opts.add_option(cmdoptions.only_binary())
        cmd_opts.add_option(cmdoptions.src())
        cmd_opts.add_option(cmdoptions.pre())
        cmd_opts.add_option(cmdoptions.no_clean())
        cmd_opts.add_option(cmdoptions.require_hashes())

        index_opts = cmdoptions.make_option_group(
            cmdoptions.non_deprecated_index_group,
            self.parser,
        )

        self.parser.insert_option_group(0, index_opts)
        self.parser.insert_option_group(0, cmd_opts)

    def run(self, options, args):
        with self._build_session(options) as session:
            finder = self._build_package_finder(
                options=options,
                session=session
            )
            from pip.req import RequirementSet	
            requirement_set = RequirementSet(
                build_dir='',
                src_dir='',
                download_dir='',
                session=session
            )
            self.populate_requirement_set(
                requirement_set,
                args,
                options,
                finder,
                session,
                self.name,
                None
            )
            for req in requirement_set.requirements.values():
                all_candidates = finder.find_all_candidates(req.name)
		compatible_versions = set(
		    req.specifier.filter(
			[str(c.version) for c in all_candidates],
			prereleases=(
			    finder.allow_all_prereleases
			    if finder.allow_all_prereleases else None
			),
		    )
		)
		applicable_candidates = [
		    c for c in all_candidates if str(c.version) in compatible_versions
		]
		if applicable_candidates:
		    best = max(applicable_candidates,
		                         key=finder._candidate_sort_key)
                    if best is not None:
                        print('%s,%s' % (best.project, best.version))
                        continue
                print('%s,' % req.name)

def prepare_files(self, finder):
    """
    Prepare process. Create temp directories, download and/or unpack files.
    """
    # make the wheelhouse
    if self.wheel_download_dir:
        from pip.utils import ensure_dir
        ensure_dir(self.wheel_download_dir)

    # If any top-level requirement has a hash specified, enter
    # hash-checking mode, which requires hashes from all.
    root_reqs = self.unnamed_requirements + self.requirements.values()
    require_hashes = (self.require_hashes or
                      any(req.has_hash_options for req in root_reqs))
    if require_hashes and self.as_egg:
        from pip.exceptions import InstallationError
        raise InstallationError(
            '--egg is not allowed with --require-hashes mode, since it '
            'delegates dependency resolution to setuptools and could thus '
            'result in installation of unhashed packages.')

    # Actually prepare the files, and collect any exceptions. Most hash
    # exceptions cannot be checked ahead of time, because
    # req.populate_link() needs to be called before we can make decisions
    # based on link type.
    discovered_reqs = []
    from pip.exceptions import HashError, HashErrors
    hash_errors = HashErrors()
    for req in root_reqs:
        try:
            discovered_reqs.extend(self._prepare_file(
                finder,
                req,
                require_hashes=require_hashes,
                ignore_dependencies=self.ignore_dependencies))
        except HashError as exc:
            exc.req = req
            hash_errors.append(exc)

    for req in discovered_reqs:
        print('%s,%s,%s' % (req.req.name, req.specifier, ' '.join(req.extras)))

    if hash_errors:
        raise hash_errors

def _to_install(self):
    return [self.requirements.values()[0]]

def patch():
    import pip.commands
    pip.commands.commands_dict[ResolveCommand.name] = ResolveCommand
    from pip.req import RequirementSet
    RequirementSet.prepare_files = prepare_files
    RequirementSet._to_install = _to_install

if __name__ == '__main__':
    patch()
    sys.exit(pip.main(sys.argv[1:]))
