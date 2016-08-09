include header.mk

ucafs: main.cc $(OBJS)
	$(CXX) $(CPPFLAGS) $^ $(LIBS) -o $@

%.o: %.cc %.h
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

filebox.o: filebox.cc filebox.h fbox.pb.cc
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

fbox.pb.cc: fbox.proto
	protoc --cpp_out=./ $^

.PHONY: clean
clean:
	rm -rf fbox.pb.h fbox.pb.cc $(PROGRAM) $(OBJS)
